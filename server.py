#!/usr/bin/env python3
"""
Network Monitor — Modern self-hosted monitoring dashboard.

Features: real-time WebSocket, SSH metrics, multi-user auth,
alerting, history graphs, Swagger API docs, maintenance windows,
SSL expiry, ping, Docker monitoring, bandwidth tracking.
"""

import asyncio
import calendar
import http.client
import json
import logging
import os
import secrets
import shutil
import smtplib
import socket
import sqlite3
import ssl
import struct
import subprocess
import time
from contextlib import asynccontextmanager
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from pathlib import Path
from typing import Optional

import aiohttp
import bcrypt
import paramiko
from fastapi import FastAPI, WebSocket, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from dotenv import load_dotenv
load_dotenv()

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("netmon")

BASE_DIR = Path(__file__).parent
DB_PATH = Path(os.environ.get("DB_PATH", str(BASE_DIR / "monitor.db")))
SESSIONS: dict[str, dict] = {}  # token -> {user_id, username, role, expires}
CHECK_INTERVAL = int(os.environ.get("CHECK_INTERVAL", "20"))
DOCKER_SOCKET = os.environ.get("DOCKER_SOCKET", "/var/run/docker.sock")

# Email alerting config
SMTP_HOST = os.environ.get("NETMON_SMTP_HOST", "")
SMTP_PORT = int(os.environ.get("NETMON_SMTP_PORT", "587"))
SMTP_USER = os.environ.get("NETMON_SMTP_USER", "")
SMTP_PASS = os.environ.get("NETMON_SMTP_PASS", "")
ALERT_EMAIL = os.environ.get("NETMON_ALERT_EMAIL", "")

# ─── Models ─────────────────────────────────────────────────────────

class ServerIn(BaseModel):
    name: str
    host: str
    check_type: str = "host"
    target: Optional[str] = None
    port: Optional[int] = None
    enabled: bool = True
    ssh_user: Optional[str] = None
    ssh_key: Optional[str] = None
    ssh_password: Optional[str] = None
    expected_status: Optional[int] = None
    health_path: Optional[str] = None

class LoginIn(BaseModel):
    username: str
    password: str

class UserIn(BaseModel):
    username: str
    password: str
    role: str = "user"

class AlertRuleIn(BaseModel):
    server_id: int
    metric: str
    threshold: float
    enabled: bool = True

class MaintenanceWindowIn(BaseModel):
    server_id: int
    start_hour: int
    start_minute: int
    end_hour: int
    end_minute: int
    days_of_week: str = "0,1,2,3,4,5,6"  # 0=Mon
    enabled: bool = True

# ─── Database ───────────────────────────────────────────────────────

def get_db():
    conn = sqlite3.connect(str(DB_PATH), timeout=30)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA busy_timeout=30000")
    return conn

def init_db():
    db = get_db()
    db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user',
            created_at REAL NOT NULL
        );
        CREATE TABLE IF NOT EXISTS servers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL, host TEXT NOT NULL,
            check_type TEXT NOT NULL DEFAULT 'host',
            target TEXT, port INTEGER,
            enabled INTEGER NOT NULL DEFAULT 1,
            ssh_user TEXT, ssh_key TEXT, ssh_password TEXT,
            cpu_model TEXT,
            expected_status INTEGER,
            health_path TEXT,
            created_at REAL NOT NULL, updated_at REAL NOT NULL
        );
        CREATE TABLE IF NOT EXISTS checks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            server_id INTEGER NOT NULL, timestamp REAL NOT NULL,
            online INTEGER NOT NULL, response_ms REAL,
            cpu REAL, ram_used REAL, ram_total REAL, ram_percent REAL,
            disk_used REAL, disk_total REAL, disk_percent REAL,
            uptime REAL, load_1 REAL, load_5 REAL, load_15 REAL,
            ping_ms REAL, ssl_days INTEGER, docker_status TEXT,
            rx_bytes REAL, tx_bytes REAL, bandwidth_rx REAL, bandwidth_tx REAL,
            detail TEXT, FOREIGN KEY(server_id) REFERENCES servers(id)
        );
        CREATE TABLE IF NOT EXISTS alert_rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            server_id INTEGER NOT NULL,
            metric TEXT NOT NULL,
            threshold REAL NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 1,
            last_triggered REAL DEFAULT 0,
            FOREIGN KEY(server_id) REFERENCES servers(id)
        );
        CREATE TABLE IF NOT EXISTS alert_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            server_id INTEGER NOT NULL,
            rule_id INTEGER,
            message TEXT NOT NULL,
            severity TEXT NOT NULL DEFAULT 'warning',
            timestamp REAL NOT NULL,
            FOREIGN KEY(server_id) REFERENCES servers(id)
        );
        CREATE TABLE IF NOT EXISTS maintenance_windows (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            server_id INTEGER NOT NULL,
            start_hour INTEGER NOT NULL,
            start_minute INTEGER NOT NULL,
            end_hour INTEGER NOT NULL,
            end_minute INTEGER NOT NULL,
            days_of_week TEXT NOT NULL DEFAULT '0,1,2,3,4,5,6',
            enabled INTEGER NOT NULL DEFAULT 1,
            FOREIGN KEY(server_id) REFERENCES servers(id)
        );
        CREATE INDEX IF NOT EXISTS idx_checks_ts ON checks(server_id, timestamp);
        CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alert_log(timestamp);
    """)
    # Migrate columns if missing
    for col, dtype in [("cpu_model", "TEXT"), ("expected_status", "INTEGER"), ("health_path", "TEXT")]:
        try:
            db.execute(f"ALTER TABLE servers ADD COLUMN {col} {dtype}")
        except Exception:
            pass
    for col, dtype in [("ping_ms", "REAL"), ("ssl_days", "INTEGER"), ("docker_status", "TEXT"),
                        ("rx_bytes", "REAL"), ("tx_bytes", "REAL"), ("bandwidth_rx", "REAL"), ("bandwidth_tx", "REAL")]:
        try:
            db.execute(f"ALTER TABLE checks ADD COLUMN {col} {dtype}")
        except Exception:
            pass
    existing = db.execute("SELECT id FROM users WHERE username='admin'").fetchone()
    if not existing:
        pw_hash = bcrypt.hashpw(b"admin", bcrypt.gensalt()).decode()
        db.execute("INSERT INTO users(username,password_hash,role,created_at) VALUES(?,?,?,?)",
                   ("admin", pw_hash, "admin", time.time()))
    db.commit()
    db.close()

# ─── Auth helpers ───────────────────────────────────────────────────

def hash_password(pw: str) -> str:
    return bcrypt.hashpw(pw.encode(), bcrypt.gensalt()).decode()

def verify_password(pw: str, hashed: str) -> bool:
    return bcrypt.checkpw(pw.encode(), hashed.encode())

def is_authed(request: Request) -> dict:
    token = request.headers.get("x-session") or request.cookies.get("netmon_token")
    if token and token in SESSIONS:
        session = SESSIONS[token]
        if session["expires"] > time.time():
            return session
    raise HTTPException(401, "Unauthorized")

def require_admin(request: Request):
    session = is_authed(request)
    if session["role"] != "admin":
        raise HTTPException(403, "Admin access required")

# ─── WebSocket ──────────────────────────────────────────────────────

class ConnectionManager:
    def __init__(self):
        self.connections: list[tuple[WebSocket, str]] = []

    async def connect(self, ws: WebSocket, token: str):
        await ws.accept()
        self.connections.append((ws, token))

    def disconnect(self, ws: WebSocket):
        self.connections = [(w, t) for w, t in self.connections if w is not ws]

    async def broadcast(self, payload: dict):
        dead = []
        for ws, _ in self.connections:
            try:
                await ws.send_json(payload)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(ws)

manager = ConnectionManager()
latest_status = {"servers": [], "timestamp": None}
monitor_task = None

# ─── Alerting ───────────────────────────────────────────────────────

def build_alert_html(server_name: str, metric: str, value: float, threshold: float, timestamp: str, top_processes: str = "") -> str:
    metric_labels = {"cpu": "CPU Usage", "ram": "RAM Usage", "disk": "Disk Usage", "response_ms": "Response Time", "ssl_days": "SSL Expiry"}
    metric_units = {"cpu": "%", "ram": "%", "disk": "%", "response_ms": "ms", "ssl_days": " days"}
    metric_icons = {"cpu": "⚙️", "ram": "💾", "disk": "💿", "response_ms": "⏱️", "ssl_days": "🔒"}
    label = metric_labels.get(metric, metric)
    unit = metric_units.get(metric, "")
    icon = metric_icons.get(metric, "⚠️")
    percent = min(int((value / threshold) * 100), 100) if threshold > 0 else 0
    return f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"></head>
<body style="margin:0;padding:0;background:#0f172a;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;">
<div style="max-width:520px;margin:0 auto;padding:32px 16px;">
  <div style="text-align:center;margin-bottom:28px;">
    <div style="display:inline-block;background:#1e293b;border:1px solid #334155;border-radius:16px;padding:20px 28px;">
      <div style="font-size:36px;margin-bottom:8px;">{icon}</div>
      <div style="color:#f87171;font-size:13px;font-weight:600;text-transform:uppercase;letter-spacing:1.5px;margin-bottom:4px;">⚠️ Alert Triggered</div>
      <div style="color:#f1f5f9;font-size:22px;font-weight:700;">{label}</div>
      <div style="color:#94a3b8;font-size:14px;margin-top:4px;">on <strong style="color:#e2e8f0;">{server_name}</strong></div>
    </div>
  </div>
  <div style="background:#1e293b;border:1px solid #334155;border-radius:14px;padding:24px;margin-bottom:20px;">
    <table width="100%" cellpadding="0" cellspacing="0">
      <tr><td style="color:#94a3b8;font-size:13px;">Current Value</td><td style="color:#94a3b8;font-size:13px;text-align:right;">Threshold</td></tr>
      <tr><td style="color:#f87171;font-size:32px;font-weight:700;padding-top:4px;">{value}{unit}</td><td style="color:#f1f5f9;font-size:32px;font-weight:700;padding-top:4px;text-align:right;">{threshold}{unit}</td></tr>
    </table>
    <div style="background:#0f172a;border-radius:8px;height:10px;margin-top:16px;overflow:hidden;">
      <div style="background:linear-gradient(90deg,#f97316,#ef4444);height:100%;width:{percent}%;border-radius:8px;"></div>
    </div>
    <div style="color:#64748b;font-size:12px;margin-top:6px;text-align:right;">{percent}% of threshold</div>
  </div>
  <div style="background:#1e293b;border:1px solid #334155;border-radius:14px;padding:20px;margin-bottom:24px;">
    <table width="100%" cellpadding="0" cellspacing="0" style="font-size:14px;">
      <tr><td style="color:#94a3b8;padding:6px 0;">Server</td><td style="color:#f1f5f9;text-align:right;font-weight:600;">{server_name}</td></tr>
      <tr><td style="color:#94a3b8;padding:6px 0;">Metric</td><td style="color:#f1f5f9;text-align:right;font-weight:600;">{label}</td></tr>
      <tr><td style="color:#94a3b8;padding:6px 0;">Time</td><td style="color:#f1f5f9;text-align:right;font-weight:600;">{timestamp}</td></tr>
      <tr><td style="color:#94a3b8;padding:6px 0;">Status</td><td style="text-align:right;"><span style="background:#7f1d1d;color:#fca5a5;padding:3px 10px;border-radius:99px;font-size:12px;font-weight:600;">THRESHOLD EXCEEDED</span></td></tr>
    </table>
  </div>
  {f"""<div style=\"background:#1e293b;border:1px solid #334155;border-radius:14px;padding:20px;margin-bottom:24px;\">
    <div style=\"color:#94a3b8;font-size:13px;font-weight:600;text-transform:uppercase;letter-spacing:1px;margin-bottom:12px;\">🔥 Top Processes by CPU</div>
    <pre style=\"color:#e2e8f0;font-size:13px;margin:0;white-space:pre-wrap;word-break:break-all;font-family:monospace;\">{top_processes}</pre>
  </div>""" if top_processes else ""}
  <div style="text-align:center;color:#475569;font-size:12px;padding:8px 0;">
    <div style="margin-bottom:4px;">This alert was sent by <strong style="color:#94a3b8;">Network Monitor</strong></div>
    <div>Server checked every {CHECK_INTERVAL}s · Alert cooldown: 5 min</div>
  </div>
</div>
</body></html>"""


def send_alert_email(subject: str, body: str, server_name: str = "", metric: str = "", value: float = 0, threshold: float = 0, top_processes: str = ""):
    if not all([SMTP_HOST, SMTP_USER, SMTP_PASS, ALERT_EMAIL]):
        return
    try:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        html = build_alert_html(server_name, metric, value, threshold, timestamp, top_processes)
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = SMTP_USER
        msg["To"] = ALERT_EMAIL
        msg.attach(MIMEText(body, "plain", "utf-8"))
        msg.attach(MIMEText(html, "html", "utf-8"))
        if SMTP_PORT == 465:
            with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT) as server:
                server.login(SMTP_USER, SMTP_PASS)
                server.sendmail(SMTP_USER, [ALERT_EMAIL], msg.as_string())
        else:
            with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
                server.starttls()
                server.login(SMTP_USER, SMTP_PASS)
                server.sendmail(SMTP_USER, [ALERT_EMAIL], msg.as_string())
        logger.info(f"Alert email sent to {ALERT_EMAIL}")
    except Exception as e:
        logger.error(f"Failed to send alert email: {e}")


def is_maintenance_window(server_id: int, db=None) -> bool:
    """Check if current time falls within a maintenance window for this server."""
    own_db = db is None
    if own_db:
        db = get_db()
    now = datetime.now()
    current_weekday = now.weekday()  # 0=Mon
    current_minutes = now.hour * 60 + now.minute
    windows = db.execute(
        "SELECT start_hour, start_minute, end_hour, end_minute, days_of_week FROM maintenance_windows WHERE server_id=? AND enabled=1",
        (server_id,)
    ).fetchall()
    result = False
    for sh, sm, eh, em, days in windows:
        start_m = sh * 60 + sm
        end_m = eh * 60 + em
        day_list = [int(d.strip()) for d in days.split(",")]
        if current_weekday in day_list:
            if start_m <= end_m:
                if start_m <= current_minutes <= end_m:
                    result = True
                    break
            else:
                if current_minutes >= start_m or current_minutes <= end_m:
                    result = True
                    break
    if own_db:
        db.close()
    return result


def check_alerts(server_id: int, server_name: str, metrics: dict, db=None, top_processes: str = ""):
    """Check alert rules and trigger if thresholds exceeded."""
    own_db = db is None
    if own_db:
        db = get_db()
    now = time.time()
    # Skip if in maintenance window
    if is_maintenance_window(server_id, db):
        if own_db:
            db.close()
        return
    rules = db.execute("SELECT id, metric, threshold, last_triggered FROM alert_rules WHERE server_id=? AND enabled=1",
                       (server_id,)).fetchall()
    for rule_id, metric, threshold, last_triggered in rules:
        value = metrics.get(metric)
        if value is None:
            continue
        if now - last_triggered < 300:
            continue
        if value > threshold:
            msg = f"[ALERT] {server_name}: {metric} is {value} (threshold: {threshold})"
            logger.warning(msg)
            db.execute("INSERT INTO alert_log(server_id,rule_id,message,severity,timestamp) VALUES(?,?,?,?,?)",
                       (server_id, rule_id, msg, "warning", now))
            db.execute("UPDATE alert_rules SET last_triggered=? WHERE id=?", (now, rule_id))
            send_alert_email(
                subject=f"[Network Monitor] ⚠️ {server_name} — {metric} exceeded",
                body=f"Server: {server_name}\nMetric: {metric}\nCurrent value: {value}\nThreshold: {threshold}\n\nTime: {datetime.fromtimestamp(now).isoformat()}",
                server_name=server_name,
                metric=metric,
                value=value,
                threshold=threshold,
                top_processes=top_processes,
            )
    if own_db:
        db.commit(); db.close()

# ─── Check functions ────────────────────────────────────────────────

async def check_http(url: str, expected_status: Optional[int] = None):
    try:
        start = time.time()
        async with aiohttp.ClientSession() as s:
            async with s.get(url, timeout=aiohttp.ClientTimeout(total=10), ssl=False) as r:
                online = r.status < 500
                if expected_status and r.status != expected_status:
                    online = False
                    detail = f"HTTP {r.status} (expected {expected_status})"
                else:
                    detail = f"HTTP {r.status}"
                return {"online": online, "response_ms": round((time.time() - start) * 1000, 1), "detail": detail, "status_code": r.status}
    except asyncio.TimeoutError:
        return {"online": False, "response_ms": None, "detail": "Timeout", "status_code": None}
    except Exception as e:
        return {"online": False, "response_ms": None, "detail": str(e)[:120], "status_code": None}

async def check_tcp(host: str, port: int):
    try:
        start = time.time()
        _, w = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=5)
        w.close(); await w.wait_closed()
        return {"online": True, "response_ms": round((time.time() - start) * 1000, 1), "detail": f"TCP {port} open"}
    except Exception as e:
        return {"online": False, "response_ms": None, "detail": str(e)[:120]}

async def check_host(host: str):
    for port in (80, 443, 22, 8080, 3000, 8123):
        try:
            start = time.time()
            _, w = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=3)
            w.close(); await w.wait_closed()
            return {"online": True, "response_ms": round((time.time() - start) * 1000, 1), "detail": f"Reachable on {port}"}
        except Exception:
            continue
    return {"online": False, "response_ms": None, "detail": "Host unreachable"}

async def check_ping(host: str):
    """ICMP ping check using system ping command."""
    try:
        ping_cmd = ["ping", "-c", "1", "-W", "2", host]
        proc = await asyncio.create_subprocess_exec(
            *ping_cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, _ = await asyncio.wait_for(proc.wait(), timeout=5)
        # Re-read output
        proc2 = await asyncio.create_subprocess_exec(
            *ping_cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout_data, _ = await asyncio.wait_for(proc2.communicate(), timeout=5)
        output = stdout_data.decode()
        # Extract time
        ms = None
        for line in output.splitlines():
            if "time=" in line:
                try:
                    ms = float(line.split("time=")[1].split(" ")[0])
                except:
                    pass
        if ms is not None:
            return {"online": True, "response_ms": round(ms, 1), "ping_ms": round(ms, 1), "detail": f"Ping {round(ms,1)}ms"}
        return {"online": False, "response_ms": None, "ping_ms": None, "detail": "No ping response"}
    except Exception as e:
        return {"online": False, "response_ms": None, "ping_ms": None, "detail": str(e)[:120]}


def check_ssl_expiry(hostname: str, port: int = 443):
    """Check SSL certificate expiry days."""
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                expiry = cert.get("notAfter")
                if expiry:
                    expiry_date = datetime.strptime(expiry, "%b %d %H:%M:%S %Y %Z")
                    days_remaining = (expiry_date - datetime.utcnow()).days
                    return {"online": True, "ssl_days": days_remaining, "detail": f"SSL expires in {days_remaining} days"}
        return {"online": False, "ssl_days": None, "detail": "No SSL cert"}
    except Exception as e:
        return {"online": False, "ssl_days": None, "detail": str(e)[:120]}


def docker_api_get(path: str):
    """Make a GET request to Docker Unix socket."""
    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect(DOCKER_SOCKET)
        request = f"GET {path} HTTP/1.1\r\nHost: localhost\r\n\r\n"
        sock.sendall(request.encode())
        response = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            response += chunk
            if b"\r\n\r\n" in response and len(response) > 1024:
                break
        sock.close()
        # Parse HTTP response
        header_end = response.find(b"\r\n\r\n")
        if header_end == -1:
            return None
        body = response[header_end + 4:]
        try:
            return json.loads(body.decode())
        except:
            return None
    except Exception as e:
        logger.error(f"Docker API error: {e}")
        return None


async def check_docker():
    """Check Docker container stats."""
    try:
        containers = docker_api_get("/containers/json")
        if containers is None:
            return {"online": False, "docker_status": None, "detail": "Docker socket unreachable"}
        status_lines = []
        for c in containers[:10]:
            name = c.get("Names", [""])[0].lstrip("/")
            state = c.get("State", "unknown")
            status = c.get("Status", "")
            status_lines.append(f"{name}: {state} ({status})")
        docker_status = "\n".join(status_lines) if status_lines else "No containers"
        return {"online": True, "docker_status": docker_status, "detail": f"{len(containers)} containers"}
    except Exception as e:
        return {"online": False, "docker_status": None, "detail": str(e)[:120]}


def get_ssh_metrics(host, port, user, key_path, password=None):
    r = {"online": False, "response_ms": None, "cpu": None, "cpu_model": None, "ram_used": None, "ram_total": None,
         "ram_percent": None, "disk_used": None, "disk_total": None, "disk_percent": None,
         "uptime": None, "load_1": None, "load_5": None, "load_15": None,
         "rx_bytes": None, "tx_bytes": None, "bandwidth_rx": None, "bandwidth_tx": None,
         "detail": ""}
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        start = time.time()
        if key_path:
            ssh.connect(host, port=port, username=user, key_filename=os.path.expanduser(key_path), timeout=10)
        else:
            ssh.connect(host, port=port, username=user, password=password, timeout=10)
        r["response_ms"] = round((time.time() - start) * 1000, 1)
        for label, cmd in [("cpu_model","cat /proc/cpuinfo 2>/dev/null | grep 'model name' | head -1 | cut -d: -f2 | xargs || uname -m"),
                           ("cpu","top -bn1 | grep 'Cpu(s)' | awk '{print $2}' | cut -d'%' -f1"),
                           ("ram","free -b | grep Mem | awk '{print $3,$2}'"),
                           ("disk","df -B1 / | tail -1 | awk '{print $3,$2}'"),
                           ("uptime","cat /proc/uptime | awk '{print $1}'"),
                           ("load","cat /proc/loadavg | awk '{print $1,$2,$3}'"),
                           ("net","cat /proc/net/dev | grep -E 'eth|enp|ens|wlan' | head -1 | awk '{print $2,$10}'"),
                           ("processes","ps aux --sort=-%cpu | head -6 | awk '{printf \"%-10s %5s %5s %s\\n\", $2, $3, $4, $11}'")]:
            _, stdout, _ = ssh.exec_command(cmd, timeout=5)
            raw = stdout.read().decode().strip()
            if label == "cpu_model":
                r["cpu_model"] = raw if raw else None
            elif label == "cpu":
                try: r["cpu"] = float(raw)
                except: r["cpu"] = 0.0
            elif label == "ram":
                p = raw.split()
                if len(p) == 2:
                    r["ram_used"] = int(p[0]); r["ram_total"] = int(p[1])
                    r["ram_percent"] = round(int(p[0]) / int(p[1]) * 100, 1) if int(p[1]) > 0 else None
            elif label == "disk":
                p = raw.split()
                if len(p) == 2:
                    r["disk_used"] = int(p[0]); r["disk_total"] = int(p[1])
                    r["disk_percent"] = round(int(p[0]) / int(p[1]) * 100, 1) if int(p[1]) > 0 else None
            elif label == "uptime":
                try: r["uptime"] = float(raw)
                except: pass
            elif label == "load":
                p = raw.split()
                if len(p) == 3:
                    r["load_1"] = float(p[0]); r["load_5"] = float(p[1]); r["load_15"] = float(p[2])
            elif label == "net":
                p = raw.split()
                if len(p) == 2:
                    r["rx_bytes"] = int(p[0]); r["tx_bytes"] = int(p[1])
            elif label == "processes":
                r["top_processes"] = raw
        ssh.close()
        r["online"] = True; r["detail"] = "SSH OK"
    except Exception as e:
        r["detail"] = str(e)[:120]
    return r


async def check_ssh(host, port, user, key_path, password=None):
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, lambda: get_ssh_metrics(host, port or 22, user, key_path, password))


# ─── Monitor loop ───────────────────────────────────────────────────

async def run_monitor_loop():
    global latest_status
    prev_net = {}  # server_id -> (rx, tx, timestamp)
    while True:
        try:
            db = get_db(); db.row_factory = sqlite3.Row
            rows = [dict(r) for r in db.execute("SELECT * FROM servers WHERE enabled=1 ORDER BY name").fetchall()]
            db.close()

            now = time.time()
            results = []
            check_rows = []

            for row in rows:
                ct = row["check_type"]
                if ct == "ssh":
                    s = await check_ssh(row["host"], row.get("port") or 22, row.get("ssh_user") or "root", row.get("ssh_key"), row.get("ssh_password"))
                elif ct == "http":
                    target = row.get("target") or f"http://{row['host']}"
                    if row.get("health_path"):
                        target = target.rstrip("/") + "/" + row["health_path"].lstrip("/")
                    s = await check_http(target, row.get("expected_status"))
                elif ct == "https":
                    target = row.get("target") or f"https://{row['host']}"
                    if row.get("health_path"):
                        target = target.rstrip("/") + "/" + row["health_path"].lstrip("/")
                    s = await check_http(target, row.get("expected_status"))
                elif ct == "tcp":
                    s = await check_tcp(row["host"], row.get("port") or 80)
                elif ct == "ping":
                    s = await check_ping(row["host"])
                elif ct == "ssl":
                    s = check_ssl_expiry(row["host"], row.get("port") or 443)
                elif ct == "docker":
                    s = await check_docker()
                else:
                    s = await check_host(row["host"])
                check_rows.append((row, s))
                row.update(s)
                results.append(row)

            db = get_db()
            for row, s in check_rows:
                # Calculate bandwidth if we have previous net data
                sid = row["id"]
                rx = s.get("rx_bytes")
                tx = s.get("tx_bytes")
                bw_rx = None
                bw_tx = None
                if rx is not None and tx is not None and sid in prev_net:
                    prev_rx, prev_tx, prev_ts = prev_net[sid]
                    dt = now - prev_ts
                    if dt > 0:
                        bw_rx = max(0, (rx - prev_rx) / dt)
                        bw_tx = max(0, (tx - prev_tx) / dt)
                if rx is not None and tx is not None:
                    prev_net[sid] = (rx, tx, now)

                db.execute("""INSERT INTO checks(
                    server_id,timestamp,online,response_ms,cpu,ram_used,ram_total,ram_percent,
                    disk_used,disk_total,disk_percent,uptime,load_1,load_5,load_15,
                    ping_ms,ssl_days,docker_status,rx_bytes,tx_bytes,bandwidth_rx,bandwidth_tx,detail)
                    VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (sid, now, int(s.get("online", False)), s.get("response_ms"), s.get("cpu"),
                     s.get("ram_used"), s.get("ram_total"), s.get("ram_percent"),
                     s.get("disk_used"), s.get("disk_total"), s.get("disk_percent"),
                     s.get("uptime"), s.get("load_1"), s.get("load_5"), s.get("load_15"),
                     s.get("ping_ms"), s.get("ssl_days"), s.get("docker_status"),
                     rx, tx, bw_rx, bw_tx, s.get("detail","")))
                check_alerts(sid, row["name"], {
                    "cpu": s.get("cpu"), "ram": s.get("ram_percent"),
                    "disk": s.get("disk_percent"), "response_ms": s.get("response_ms"),
                    "ssl_days": s.get("ssl_days")
                }, db=db, top_processes=s.get("top_processes", ""))
                if s.get("cpu_model"):
                    db.execute("UPDATE servers SET cpu_model=? WHERE id=?", (s["cpu_model"], sid))
            db.execute("DELETE FROM checks WHERE timestamp < ?", (now - 7*86400,))
            db.execute("DELETE FROM alert_log WHERE timestamp < ?", (now - 30*86400,))
            db.commit(); db.close()

            latest_status = {"servers": results, "timestamp": now, "timestamp_iso": datetime.now().isoformat()}
            await manager.broadcast({"type": "status_update", "data": latest_status})
            await asyncio.sleep(CHECK_INTERVAL)
        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.error(f"monitor: {e}"); await asyncio.sleep(5)

# ─── App ────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    global monitor_task
    init_db()
    monitor_task = asyncio.create_task(run_monitor_loop())
    logger.info("Network Monitor started")
    yield
    if monitor_task: monitor_task.cancel()

app = FastAPI(
    title="Network Monitor API",
    description="Modern self-hosted network monitoring dashboard with real-time WebSocket updates, SSH metrics, and alerting.",
    version="1.4.0",
    lifespan=lifespan,
)
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")

# ─── Pages ──────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse, include_in_schema=False)
async def index():
    return (BASE_DIR / "static" / "index.html").read_text()

@app.get("/login", response_class=HTMLResponse, include_in_schema=False)
async def login_page():
    return (BASE_DIR / "static" / "login.html").read_text()

# ─── Auth API ───────────────────────────────────────────────────────

@app.post("/api/login", tags=["auth"])
async def api_login(body: LoginIn):
    db = get_db(); db.row_factory = sqlite3.Row
    user = db.execute("SELECT * FROM users WHERE username=?", (body.username,)).fetchone()
    db.close()
    if user and verify_password(body.password, user["password_hash"]):
        token = secrets.token_hex(32)
        SESSIONS[token] = {"user_id": user["id"], "username": user["username"], "role": user["role"], "expires": time.time() + 86400}
        return {"ok": True, "token": token, "role": user["role"]}
    raise HTTPException(401, "Invalid credentials")

@app.get("/api/check-auth", tags=["auth"])
async def check_auth_ep(request: Request):
    try:
        session = is_authed(request)
        return {"authed": True, "username": session["username"], "role": session["role"]}
    except HTTPException:
        return {"authed": False}

@app.get("/api/health", tags=["system"])
async def health():
    return {"status": "ok", "timestamp": datetime.now().isoformat(), "version": "1.4.0"}

# ─── Servers API ────────────────────────────────────────────────────

@app.get("/api/servers", tags=["servers"])
async def list_servers(request: Request):
    is_authed(request)
    db = get_db(); db.row_factory = sqlite3.Row
    rows = [dict(r) for r in db.execute(
        "SELECT id,name,host,check_type,target,port,enabled,ssh_user,ssh_key,expected_status,health_path,created_at,updated_at FROM servers ORDER BY name"
    ).fetchall()]
    db.close()
    return rows

@app.post("/api/servers", tags=["servers"])
async def create_server(request: Request, server: ServerIn):
    is_authed(request)
    now = time.time(); db = get_db()
    cur = db.execute(
        "INSERT INTO servers(name,host,check_type,target,port,enabled,ssh_user,ssh_key,ssh_password,expected_status,health_path,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (server.name, server.host, server.check_type, server.target, server.port, int(server.enabled),
         server.ssh_user, server.ssh_key, server.ssh_password, server.expected_status, server.health_path, now, now))
    db.commit(); new_id = cur.lastrowid; db.close()
    return {"ok": True, "id": new_id}

@app.put("/api/servers/{sid}", tags=["servers"])
async def update_server(request: Request, sid: int, server: ServerIn):
    is_authed(request)
    db = get_db()
    cur = db.execute(
        "UPDATE servers SET name=?,host=?,check_type=?,target=?,port=?,enabled=?,ssh_user=?,ssh_key=?,ssh_password=?,expected_status=?,health_path=?,updated_at=? WHERE id=?",
        (server.name, server.host, server.check_type, server.target, server.port, int(server.enabled),
         server.ssh_user, server.ssh_key, server.ssh_password, server.expected_status, server.health_path, time.time(), sid))
    db.commit(); db.close()
    if cur.rowcount == 0: raise HTTPException(404, "Not found")
    return {"ok": True}

@app.delete("/api/servers/{sid}", tags=["servers"])
async def delete_server(request: Request, sid: int):
    is_authed(request)
    db = get_db(); db.execute("DELETE FROM checks WHERE server_id=?", (sid,))
    db.execute("DELETE FROM alert_rules WHERE server_id=?", (sid,))
    db.execute("DELETE FROM alert_log WHERE server_id=?", (sid,))
    db.execute("DELETE FROM maintenance_windows WHERE server_id=?", (sid,))
    cur = db.execute("DELETE FROM servers WHERE id=?", (sid,)); db.commit(); db.close()
    if cur.rowcount == 0: raise HTTPException(404, "Not found")
    return {"ok": True}

# ─── History API ────────────────────────────────────────────────────

@app.get("/api/history/{sid}", tags=["history"])
async def get_history(request: Request, sid: int, hours: int = 6):
    is_authed(request)
    cutoff = time.time() - (hours * 3600)
    db = get_db()
    rows = db.execute(
        "SELECT timestamp,online,response_ms,cpu,ram_percent,disk_percent,load_1,ram_total,ping_ms,ssl_days,rx_bytes,tx_bytes,bandwidth_rx,bandwidth_tx FROM checks WHERE server_id=? AND timestamp>? ORDER BY timestamp",
        (sid, cutoff)).fetchall()
    server_row = db.execute("SELECT cpu_model FROM servers WHERE id=?", (sid,)).fetchone()
    cpu_model = server_row[0] if server_row else None
    db.close()
    return {
        "cpu_model": cpu_model,
        "data": [{"timestamp": r[0], "online": bool(r[1]), "response_ms": r[2], "cpu": r[3], "ram_percent": r[4], "disk_percent": r[5], "load_1": r[6], "ram_total": r[7], "ping_ms": r[8], "ssl_days": r[9], "rx_bytes": r[10], "tx_bytes": r[11], "bandwidth_rx": r[12], "bandwidth_tx": r[13]} for r in rows]
    }

# ─── Alerts API ─────────────────────────────────────────────────────

@app.get("/api/alerts", tags=["alerts"])
async def list_alerts(request: Request, limit: int = 50):
    is_authed(request)
    db = get_db(); db.row_factory = sqlite3.Row
    rows = [dict(r) for r in db.execute(
        "SELECT al.*, s.name as server_name FROM alert_log al JOIN servers s ON al.server_id=s.id ORDER BY al.timestamp DESC LIMIT ?", (limit,)).fetchall()]
    db.close()
    return rows

@app.get("/api/alert-rules", tags=["alerts"])
async def list_alert_rules(request: Request):
    is_authed(request)
    db = get_db(); db.row_factory = sqlite3.Row
    rows = [dict(r) for r in db.execute(
        "SELECT ar.*, s.name as server_name FROM alert_rules ar JOIN servers s ON ar.server_id=s.id ORDER BY s.name").fetchall()]
    db.close()
    return rows

@app.post("/api/alert-rules", tags=["alerts"])
async def create_alert_rule(request: Request, rule: AlertRuleIn):
    is_authed(request)
    db = get_db()
    cur = db.execute("INSERT INTO alert_rules(server_id,metric,threshold,enabled) VALUES(?,?,?,?)",
                     (rule.server_id, rule.metric, rule.threshold, int(rule.enabled)))
    db.commit(); new_id = cur.lastrowid; db.close()
    return {"ok": True, "id": new_id}

@app.delete("/api/alert-rules/{rid}", tags=["alerts"])
async def delete_alert_rule(request: Request, rid: int):
    is_authed(request)
    db = get_db(); cur = db.execute("DELETE FROM alert_rules WHERE id=?", (rid,))
    db.commit(); db.close()
    if cur.rowcount == 0: raise HTTPException(404, "Not found")
    return {"ok": True}

class ServerAlertIn(BaseModel):
    metric: str
    threshold: float
    enabled: bool = True

class ServerAlertsIn(BaseModel):
    alerts: list[ServerAlertIn]

@app.get("/api/servers/{sid}/alerts", tags=["alerts"])
async def get_server_alerts(request: Request, sid: int):
    is_authed(request)
    db = get_db()
    rows = db.execute(
        "SELECT id, metric, threshold, enabled, last_triggered FROM alert_rules WHERE server_id=?",
        (sid,)).fetchall()
    db.close()
    return [{"id": r[0], "metric": r[1], "threshold": r[2], "enabled": bool(r[3]), "last_triggered": r[4]} for r in rows]

@app.put("/api/servers/{sid}/alerts", tags=["alerts"])
async def save_server_alerts(request: Request, sid: int, body: ServerAlertsIn):
    is_authed(request)
    db = get_db()
    server = db.execute("SELECT name FROM servers WHERE id=?", (sid,)).fetchone()
    if not server:
        db.close(); raise HTTPException(404, "Server not found")
    db.execute("DELETE FROM alert_rules WHERE server_id=?", (sid,))
    for alert in body.alerts:
        if alert.enabled and alert.threshold > 0:
            db.execute(
                "INSERT INTO alert_rules(server_id, metric, threshold, enabled) VALUES(?,?,?,?)",
                (sid, alert.metric, alert.threshold, 1))
    db.commit(); db.close()
    return {"ok": True}

# ─── Maintenance Windows API ────────────────────────────────────────

@app.get("/api/maintenance-windows", tags=["maintenance"])
async def list_maintenance_windows(request: Request):
    is_authed(request)
    db = get_db(); db.row_factory = sqlite3.Row
    rows = [dict(r) for r in db.execute(
        "SELECT mw.*, s.name as server_name FROM maintenance_windows mw JOIN servers s ON mw.server_id=s.id ORDER BY s.name").fetchall()]
    db.close()
    return rows

@app.post("/api/maintenance-windows", tags=["maintenance"])
async def create_maintenance_window(request: Request, window: MaintenanceWindowIn):
    is_authed(request)
    db = get_db()
    cur = db.execute(
        "INSERT INTO maintenance_windows(server_id,start_hour,start_minute,end_hour,end_minute,days_of_week,enabled) VALUES(?,?,?,?,?,?,?)",
        (window.server_id, window.start_hour, window.start_minute, window.end_hour, window.end_minute, window.days_of_week, int(window.enabled)))
    db.commit(); new_id = cur.lastrowid; db.close()
    return {"ok": True, "id": new_id}

@app.delete("/api/maintenance-windows/{wid}", tags=["maintenance"])
async def delete_maintenance_window(request: Request, wid: int):
    is_authed(request)
    db = get_db(); cur = db.execute("DELETE FROM maintenance_windows WHERE id=?", (wid,))
    db.commit(); db.close()
    if cur.rowcount == 0: raise HTTPException(404, "Not found")
    return {"ok": True}

# ─── Users API (admin only) ────────────────────────────────────────

@app.get("/api/users", tags=["users"])
async def list_users(request: Request):
    require_admin(request)
    db = get_db(); db.row_factory = sqlite3.Row
    rows = [dict(r) for r in db.execute("SELECT id,username,role,created_at FROM users ORDER BY username").fetchall()]
    db.close()
    return rows

@app.post("/api/users", tags=["users"])
async def create_user(request: Request, user: UserIn):
    require_admin(request)
    if len(user.password) < 4:
        raise HTTPException(400, "Password must be at least 4 characters")
    pw_hash = hash_password(user.password)
    db = get_db()
    try:
        cur = db.execute("INSERT INTO users(username,password_hash,role,created_at) VALUES(?,?,?,?)",
                         (user.username, pw_hash, user.role, time.time()))
        db.commit(); new_id = cur.lastrowid; db.close()
        return {"ok": True, "id": new_id}
    except sqlite3.IntegrityError:
        db.close()
        raise HTTPException(400, "Username already exists")

@app.delete("/api/users/{uid}", tags=["users"])
async def delete_user(request: Request, uid: int):
    require_admin(request)
    db = get_db()
    user = db.execute("SELECT username FROM users WHERE id=?", (uid,)).fetchone()
    if not user:
        db.close(); raise HTTPException(404, "User not found")
    if user[0] == "admin":
        db.close(); raise HTTPException(400, "Cannot delete default admin")
    db.execute("DELETE FROM users WHERE id=?", (uid,)); db.commit(); db.close()
    return {"ok": True}

class PasswordIn(BaseModel):
    password: str

@app.put("/api/users/{uid}/password", tags=["users"])
async def change_password(request: Request, uid: int, body: PasswordIn):
    session = is_authed(request)
    if session["role"] != "admin" and session.get("user_id") != uid:
        raise HTTPException(403, "You can only change your own password")
    if len(body.password) < 4:
        raise HTTPException(400, "Password must be at least 4 characters")
    db = get_db()
    user = db.execute("SELECT id FROM users WHERE id=?", (uid,)).fetchone()
    if not user:
        db.close(); raise HTTPException(404, "User not found")
    pw_hash = bcrypt.hashpw(body.password.encode(), bcrypt.gensalt()).decode()
    db.execute("UPDATE users SET password_hash=? WHERE id=?", (pw_hash, uid))
    db.commit(); db.close()
    return {"ok": True}

# ─── WebSocket ──────────────────────────────────────────────────────

@app.websocket("/ws")
async def ws_endpoint(ws: WebSocket):
    await ws.accept()
    try:
        msg = await asyncio.wait_for(ws.receive_json(), timeout=5)
        token = msg.get("token")
        if not token or token not in SESSIONS or SESSIONS[token]["expires"] < time.time():
            await ws.send_json({"type": "auth_error"}); await ws.close(); return
        await ws.send_json({"type": "status_update", "data": latest_status})
        manager.connections.append((ws, token))
        while True:
            await ws.receive_text()
    except Exception:
        manager.disconnect(ws)

# ─── Main ───────────────────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("NETMON_PORT", "8765"))
    logger.info(f"Starting Network Monitor on port {port}")
    uvicorn.run(app, host="0.0.0.0", port=port)
