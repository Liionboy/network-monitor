# Network Monitor

A modern, self-hosted network monitoring dashboard with real-time updates, SSH metrics, and a beautiful dark UI.

![Python](https://img.shields.io/badge/Python-3.10+-blue)
![License](https://img.shields.io/badge/License-MIT-green)
![Version](https://img.shields.io/badge/version-1.5.1-blue)

## Features

- **Real-time monitoring** via WebSocket — instant updates without page refresh
- **Multiple check types**: Host reachability, HTTP, HTTPS, TCP port, SSH with full system metrics, Docker, and Proxmox VE
- **SSH metrics**: CPU %, RAM %, Disk %, Uptime, Load Average, CPU Model
- **History graphs** with Y/X-axis labels, stats (Avg/Min/Max), and value tooltips on hover
- **Beautiful dark UI** — glassmorphism, responsive, modern
- **Authentication** — secure login with token-based sessions
- **Email alerting** — receive alerts when thresholds are exceeded
- **Auto-start** — systemd service, starts on boot
- **Docker support** — one-command deployment
- **REST API** — full CRUD for servers, with Swagger docs at `/docs`

## Quick Start

### Option 1: Docker (recommended)

```bash
git clone https://github.com/Liionboy/network-monitor.git
cd network-monitor
docker compose up -d
```

Copy `.env.example` to `.env`, set a strong `NETMON_PASS` and generate a secret
with `openssl rand -hex 32`, then start the stack. The first admin account is
created from those values.

### Option 2: Manual install

```bash
git clone https://github.com/Liionboy/network-monitor.git
cd network-monitor

# Configure environment
cp .env.example .env
nano .env  # edit values as needed

# Install & run
pip install -r requirements.txt
python3 server.py
```

Open http://localhost:8765 — login with credentials from your `.env` file.

## Configuration

All configuration is done via environment variables. You can either:

- **Docker**: set them in `.env` (the compose file loads it)
- **Manual**: copy `.env.example` to `.env` and edit

### Environment Variables

| Variable | Default | Description |
|---|---|---|
| `NETMON_USER` | `admin` | Login username |
| `NETMON_PASS` | — | Initial login password, minimum 12 characters |
| `NETMON_SECRET` | — | At least 32 characters; encrypts stored SSH passwords and Proxmox tokens |
| `NETMON_SECURE_COOKIES` | `false` | Set `true` when served over HTTPS |
| `NETMON_SSH_KNOWN_HOSTS` | `/etc/netmon/known_hosts` | Curated SSH host-key file; unknown keys are rejected |
| `DB_PATH` | `monitor.db` | SQLite database path |
| `NETMON_PORT` | `8765` | Server listen port |
| `CHECK_INTERVAL` | `20` | Seconds between monitoring checks |
| `NETMON_SMTP_HOST` | — | SMTP server hostname |
| `NETMON_SMTP_PORT` | `587` | SMTP port (587=STARTTLS, 465=SSL) |
| `NETMON_SMTP_USER` | — | SMTP username / email |
| `NETMON_SMTP_PASS` | — | SMTP password or app password |
| `NETMON_ALERT_EMAIL` | — | Recipient email for alerts |

### Email Alerting Setup

1. Create alert rules in the dashboard (Alerts tab → Add Rule)
2. Add SMTP settings to your `.env` file:

```env
NETMON_SMTP_HOST=smtp.gmail.com
NETMON_SMTP_PORT=587
NETMON_SMTP_USER=your@email.com
NETMON_SMTP_PASS=your_app_password
NETMON_ALERT_EMAIL=recipient@email.com
```

3. Restart the server

**SMTP Providers:**
| Provider | Host | Port | Notes |
|---|---|---|---|
| Gmail | `smtp.gmail.com` | 587 | Use [App Password](https://myaccount.google.com/apppasswords) |
| Outlook | `smtp.office365.com` | 587 | |
| 163.com | `smtp.163.com` | 465 | Use authorization code |

## Check Types

| Type | What it checks | Requirements |
|---|---|---|
| **Host** | Is server reachable? (tries ports 80, 443, 22, etc.) | None |
| **HTTP** | HTTP response status | URL |
| **HTTPS** | HTTPS response status | URL |
| **TCP** | TCP port open | Host + Port |
| **SSH** | Full system metrics (CPU, RAM, Disk, Uptime, Load) | SSH access (key or password) |
| **Proxmox VE** | Cluster nodes, node health, VMs, LXC, CPU, RAM, disk and load | Read-only Proxmox API token |

### SSH Monitoring

For SSH checks, you need SSH access to the target server.

**Using SSH key (recommended):**
- Set **SSH User** (e.g., `root`, `ubuntu`)
- Set **Private Key Path** (e.g., `~/.ssh/id_rsa`)
- Leave Password empty

**Using password:**
- Set **SSH User**
- Leave Private Key empty
- Set **Password**

SSH metrics collected: CPU %, CPU Model, RAM % (used/total), Disk % (used/total), Uptime, Load Average (1/5/15 min).

### Proxmox VE Monitoring

Create a read-only API token in Proxmox and enter the token value in the
dashboard using the form `user@realm!tokenid=uuid`. Set the Proxmox API URL in
the target field, for example `https://pve.example:8006`; if it is omitted,
the monitor uses `https://<host>:8006`. TLS verification is enabled by default.
Disable it only for a deliberately trusted lab endpoint with a self-signed
certificate.

The API token is encrypted in SQLite with `NETMON_SECRET` and is never
returned by the server-list endpoint.

## API Documentation

Full Swagger/OpenAPI docs available at `/docs` when the server is running.

### Endpoints

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/status` | Current status of all servers |
| `GET` | `/api/servers` | List all configured servers |
| `POST` | `/api/servers` | Add a new server |
| `PUT` | `/api/servers/:id` | Update a server |
| `DELETE` | `/api/servers/:id` | Delete a server |
| `GET` | `/api/history/:id?hours=6` | Historical check data (CPU, RAM, Response Time) |
| `GET` | `/api/alerts` | Recent alert log entries |
| `GET` | `/api/alert-rules` | List alert rules |
| `POST` | `/api/alert-rules` | Create alert rule |
| `GET` | `/api/health` | Health check |
| `POST` | `/api/login` | Authenticate |
| `GET` | `/api/check-auth` | Verify token |
| `WS` | `/ws` | Real-time updates |

All endpoints (except `/api/login`, `/api/health`, and `/docs`) require the
HttpOnly session cookie set at login. The legacy `x-session` header remains
accepted for API clients.

## Changing Password

**Via the dashboard:**
Go to the **Users** tab (admin only) and update the password.

**Via command line:**
```bash
# Generate a bcrypt hash
python3 -c "import bcrypt; print(bcrypt.hashpw(b'YOUR_NEW_PASSWORD', bcrypt.gensalt()).decode())"

# Update in database
sqlite3 monitor.db "UPDATE users SET password_hash='PASTE_HASH_HERE' WHERE username='admin';"
```

## Systemd Service (auto-start on boot)

```bash
# Enable lingering for your user
sudo loginctl enable-linger $USER

# The service file is included in the repo
systemctl --user daemon-reload
systemctl --user enable network-monitor
systemctl --user start network-monitor

# Check status
systemctl --user status network-monitor

# View logs
journalctl --user -u network-monitor -f
```

## Tech Stack

- **Backend**: Python 3.10+, FastAPI, Uvicorn
- **Frontend**: Vanilla JS, CSS Grid, WebSocket
- **Database**: SQLite (lightweight, no setup)
- **Monitoring**: Paramiko (SSH), aiohttp (HTTP), asyncio
- **Auth**: Token-based sessions

## Project Structure

```
network-monitor/
├── server.py              # Main application
├── requirements.txt       # Python dependencies
├── .env.example           # Environment variables template
├── Dockerfile             # Docker build
├── docker-compose.yml     # Docker Compose
├── netmon.service         # Systemd service file
├── static/
│   ├── index.html         # Dashboard
│   ├── login.html         # Login page
│   ├── favicon.svg        # Favicon
│   ├── css/style.css      # Styles
│   └── js/app.js          # Frontend logic
├── LICENSE
├── README.md
└── CHANGELOG.md
```

## Contributing

1. Fork the repo
2. Create a feature branch (`git checkout -b feature/amazing`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing`)
5. Open a Pull Request

## License

MIT License — see [LICENSE](LICENSE) for details.
