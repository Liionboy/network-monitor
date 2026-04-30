let ws = null;
let currentStatus = { servers: [] };
let serversCache = [];

function getToken() { return localStorage.getItem('netmon_token'); }
function logout() { localStorage.removeItem('netmon_token'); location.href = '/login'; }

async function apiFetch(url, opts = {}) {
    opts.headers = { ...(opts.headers || {}), 'x-session': getToken() || '' };
    const res = await fetch(url, opts);
    if (res.status === 401) { logout(); return null; }
    return res;
}

// ─── Tabs ──────────────────────────────────────────────────────────

function switchTab(tab) {
    document.querySelectorAll('[id^="tab-"]').forEach(el => el.classList.add('hidden'));
    document.getElementById('tab-' + tab).classList.remove('hidden');
    document.querySelectorAll('.nav-tab').forEach(b => b.classList.remove('active'));
    event.target.classList.add('active');
    if (tab === 'alerts') { loadAlertRules(); loadAlertLog(); }
    if (tab === 'users') loadUsers();
    if (tab === 'maintenance') loadMaintenanceWindows();
}

// ─── Data loading ──────────────────────────────────────────────────

async function loadServers() {
    const res = await apiFetch('/api/servers');
    if (!res) return;
    serversCache = await res.json();
    renderServerList();
}

function connectWs() {
    const protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
    ws = new WebSocket(`${protocol}//${location.host}/ws`);
    ws.onopen = () => {
        document.getElementById('ws-status').className = 'connection-status connected';
        document.getElementById('ws-status').querySelector('.label').textContent = 'Live';
        ws.send(JSON.stringify({ token: getToken() }));
    };
    ws.onmessage = (e) => {
        const msg = JSON.parse(e.data);
        if (msg.type === 'auth_error') { logout(); return; }
        if (msg.type === 'status_update') {
            currentStatus = msg.data || { servers: [] };
            renderDashboard();
        }
    };
    ws.onclose = () => {
        document.getElementById('ws-status').className = 'connection-status disconnected';
        document.getElementById('ws-status').querySelector('.label').textContent = 'Disconnected';
        setTimeout(connectWs, 3000);
    };
}

// ─── Formatting ────────────────────────────────────────────────────

function fmtBytes(b) {
    if (!b) return '-';
    const u = ['B','KB','MB','GB','TB']; let i = 0;
    while (b >= 1024 && i < u.length-1) { b /= 1024; i++; }
    return b.toFixed(1) + ' ' + u[i];
}
function fmtUptime(s) {
    if (!s) return '-';
    const d = Math.floor(s/86400), h = Math.floor((s%86400)/3600), m = Math.floor((s%3600)/60);
    if (d > 0) return d+'d '+h+'h'; if (h > 0) return h+'h '+m+'m'; return m+'m';
}
function fmtTime(ts) {
    return new Date(ts * 1000).toLocaleString('ro-RO', { day:'2-digit', month:'2-digit', hour:'2-digit', minute:'2-digit' });
}
function esc(s) { return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }
function fmtBandwidth(bps) {
    if (!bps || bps < 0) return '-';
    if (bps >= 1e6) return (bps/1e6).toFixed(1) + ' MB/s';
    if (bps >= 1e3) return (bps/1e3).toFixed(1) + ' KB/s';
    return bps.toFixed(0) + ' B/s';
}

// ─── Dashboard ─────────────────────────────────────────────────────

function renderDashboard() {
    const servers = currentStatus.servers || [];
    const online = servers.filter(s => s.online).length;
    document.getElementById('stats-row').innerHTML =
        '<div class="mini-stat"><strong>'+servers.length+'</strong><span>Total</span></div>'+
        '<div class="mini-stat"><strong>'+online+'</strong><span>Online</span></div>'+
        '<div class="mini-stat"><strong>'+(servers.length-online)+'</strong><span>Offline</span></div>';
    document.getElementById('last-update').textContent = currentStatus.timestamp_iso
        ? new Date(currentStatus.timestamp_iso).toLocaleTimeString('ro-RO') : '--:--:--';

    const grid = document.getElementById('servers-grid');
    if (!servers.length) { grid.innerHTML = '<div class="empty">No servers. Click <b>+ Add server</b>.</div>'; return; }

    grid.innerHTML = servers.map(s => {
        let m = '';
        if (s.check_type === 'ssh' && s.online) {
            m = '<div class="metrics-row">'+
                '<div class="metric"><span class="metric-label">CPU</span><span class="metric-value">'+(s.cpu!=null?s.cpu.toFixed(1)+'%':'-')+'</span></div>'+
                '<div class="metric"><span class="metric-label">RAM</span><span class="metric-value">'+(s.ram_percent!=null?s.ram_percent.toFixed(1)+'%':'-')+'</span></div>'+
                '<div class="metric"><span class="metric-label">Disk</span><span class="metric-value">'+(s.disk_percent!=null?s.disk_percent.toFixed(1)+'%':'-')+'</span></div></div>'+
                '<div class="info-row"><span>Uptime: <b>'+fmtUptime(s.uptime)+'</b></span><span>Load: <b>'+(s.load_1||'-')+' / '+(s.load_5||'-')+' / '+(s.load_15||'-')+'</b></span></div>'+
                '<div class="info-row"><span>RAM: <b>'+fmtBytes(s.ram_used)+' / '+fmtBytes(s.ram_total)+'</b></span><span>Disk: <b>'+fmtBytes(s.disk_used)+' / '+fmtBytes(s.disk_total)+'</b></span></div>';
            if (s.bandwidth_rx || s.bandwidth_tx) {
                m += '<div class="info-row"><span>↓ <b>'+fmtBandwidth(s.bandwidth_rx)+'</b></span><span>↑ <b>'+fmtBandwidth(s.bandwidth_tx)+'</b></span></div>';
            }
            if (s.top_processes) {
                m += '<div class="info-row" style="max-height:60px;overflow-y:auto;font-size:11px;font-family:monospace;white-space:pre;color:#94a3b8;background:#0f172a;padding:4px 8px;border-radius:6px;margin-top:4px;">'+esc(s.top_processes)+'</div>';
            }
        } else if (s.check_type === 'ssl' && s.online) {
            const days = s.ssl_days;
            const color = days < 7 ? '#ef4444' : days < 30 ? '#f59e0b' : '#22c55e';
            m = '<div class="metrics-row">'+
                '<div class="metric"><span class="metric-label">SSL Expires</span><span class="metric-value" style="color:'+color+'">'+days+' days</span></div></div>';
        } else if (s.check_type === 'ping' && s.online) {
            m = '<div class="metrics-row">'+
                '<div class="metric"><span class="metric-label">Latency</span><span class="metric-value">'+(s.ping_ms?s.ping_ms.toFixed(1)+' ms':'-')+'</span></div></div>';
        } else if (s.check_type === 'docker' && s.online) {
            m = '<div class="info-row" style="max-height:100px;overflow-y:auto;font-size:11px;font-family:monospace;white-space:pre;color:#94a3b8;background:#0f172a;padding:8px;border-radius:6px;margin-top:4px;">'+esc(s.docker_status || 'No containers')+'</div>';
        }
        if (s.health_path) {
            m += '<div class="info-row"><span>Health: <b>'+esc(s.health_path)+'</b>'+(s.expected_status?' → expect '+s.expected_status:'')+'</span></div>';
        }
        return '<div class="server-card '+(s.online?'online':'offline')+'">'+
            '<div class="card-header"><div><div class="server-name">'+esc(s.name)+'</div><div class="server-host">'+esc(s.host)+'</div></div>'+
            '<div class="badge '+(s.online?'ok':'bad')+'">'+(s.online?'ONLINE':'OFFLINE')+'</div></div>'+
            m+'<div class="detail-row"><span>Check</span><span>'+esc(s.check_type.toUpperCase())+'</span></div>'+
            '<div class="detail-row"><span>Latency</span><span>'+(s.response_ms?s.response_ms+' ms':'—')+'</span></div>'+
            '<div class="detail-row"><span>Detail</span><span>'+esc(s.detail||'-')+'</span></div>'+
            '<div class="card-footer"><button class="icon-btn" onclick="openHistory('+s.id+',\''+esc(s.name)+'\')">📊 History</button> <button class="icon-btn" onclick="openServerAlerts('+s.id+',\''+esc(s.name)+'\')">⚡ Alerts</button></div></div>';
    }).join('');
}

function renderServerList() {
    const el = document.getElementById('server-list');
    if (!serversCache.length) { el.innerHTML = '<div class="empty">No servers.</div>'; return; }
    el.innerHTML = serversCache.map(s =>
        '<div class="list-item"><div><div class="list-title">'+esc(s.name)+'</div><div class="list-sub">'+esc(s.host)+' · '+esc(s.check_type.toUpperCase())+'</div></div>'+
        '<div class="list-actions"><button class="icon-btn" onclick=\''+'editServer('+JSON.stringify(s).replace(/'/g,"\\'")+')'+"'>Edit</button>"+
        '<button class="icon-btn danger" onclick="deleteServer('+s.id+",'"+esc(s.name)+"')\">Del</button></div></div>"
    ).join('');
}

// ─── Server Modal ──────────────────────────────────────────────────

function openServerModal() {
    document.getElementById('server-modal-title').textContent = 'Add server';
    document.getElementById('server-form').reset();
    document.getElementById('server-id').value = '';
    document.getElementById('f-enabled').checked = true;
    toggleCheckFields();
    document.getElementById('server-modal-overlay').classList.add('active');
}
function closeServerModal() { document.getElementById('server-modal-overlay').classList.remove('active'); }

function editServer(s) {
    document.getElementById('server-modal-title').textContent = 'Edit server';
    document.getElementById('server-id').value = s.id;
    document.getElementById('f-name').value = s.name;
    document.getElementById('f-host').value = s.host;
    document.getElementById('f-check-type').value = s.check_type;
    document.getElementById('f-target').value = s.target || '';
    document.getElementById('f-port').value = s.port || '';
    document.getElementById('f-ssh-user').value = s.ssh_user || '';
    document.getElementById('f-ssh-key').value = s.ssh_key || '';
    document.getElementById('f-ssh-password').value = '';
    document.getElementById('f-health-path').value = s.health_path || '';
    document.getElementById('f-expected-status').value = s.expected_status || '';
    document.getElementById('f-enabled').checked = !!s.enabled;
    toggleCheckFields();
    document.getElementById('server-modal-overlay').classList.add('active');
}

function toggleCheckFields() {
    const t = document.getElementById('f-check-type').value;
    document.getElementById('port-wrap').classList.toggle('hidden', t !== 'tcp' && t !== 'ssh' && t !== 'ssl');
    document.getElementById('target-wrap').classList.toggle('hidden', t !== 'http' && t !== 'https');
    document.getElementById('ssh-fields').classList.toggle('hidden', t !== 'ssh');
    document.getElementById('health-fields').classList.toggle('hidden', t !== 'http' && t !== 'https');
}

// ─── Server CRUD ───────────────────────────────────────────────────

document.getElementById('server-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const id = document.getElementById('server-id').value;
    const payload = {
        name: document.getElementById('f-name').value.trim(),
        host: document.getElementById('f-host').value.trim(),
        check_type: document.getElementById('f-check-type').value,
        target: document.getElementById('f-target').value.trim() || null,
        port: document.getElementById('f-port').value ? Number(document.getElementById('f-port').value) : null,
        ssh_user: document.getElementById('f-ssh-user').value.trim() || null,
        ssh_key: document.getElementById('f-ssh-key').value.trim() || null,
        ssh_password: document.getElementById('f-ssh-password').value || null,
        health_path: document.getElementById('f-health-path').value.trim() || null,
        expected_status: document.getElementById('f-expected-status').value ? Number(document.getElementById('f-expected-status').value) : null,
        enabled: document.getElementById('f-enabled').checked,
    };
    const url = id ? '/api/servers/' + id : '/api/servers';
    const res = await apiFetch(url, { method: id ? 'PUT' : 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify(payload) });
    if (!res || !res.ok) { alert('Error saving server.'); return; }
    closeServerModal(); await loadServers();
});

async function deleteServer(id, name) {
    if (!confirm('Delete "' + name + '"?')) return;
    const res = await apiFetch('/api/servers/' + id, { method: 'DELETE' });
    if (!res || !res.ok) return alert('Error.');
    await loadServers();
}

// ─── History ───────────────────────────────────────────────────────

async function openHistory(sid, name) {
    document.getElementById('history-modal-title').textContent = name + ' — History';
    document.getElementById('history-modal-overlay').classList.add('active');
    document.getElementById('history-body').innerHTML = '<div class="empty">Loading...</div>';
    const res = await apiFetch('/api/history/' + sid + '?hours=6');
    if (!res) return;
    const result = await res.json();
    const data = result.data || result;
    const cpuModel = result.cpu_model || null;
    const body = document.getElementById('history-body');

    if (!data.length) { body.innerHTML = '<div class="empty">No history data yet.</div>'; return; }

    const timestamps = data.map(d => d.timestamp);
    const firstTime = timestamps.length ? new Date(timestamps[0] * 1000).toLocaleTimeString([], {hour:'2-digit',minute:'2-digit'}) : '';
    const lastTime = timestamps.length ? new Date(timestamps[timestamps.length-1] * 1000).toLocaleTimeString([], {hour:'2-digit',minute:'2-digit'}) : '';

    const lastWithData = [...data].reverse().find(d => d.ram_total);
    const ramTotalGB = lastWithData ? (lastWithData.ram_total / (1024**3)).toFixed(1) : null;

    let html = '';
    const respPairs = data.filter(d => d.response_ms != null).map(d => ({v: d.response_ms, ts: d.timestamp}));
    if (respPairs.length) html += miniChart('Response Time (ms)', respPairs, Math.max(...respPairs.map(p=>p.v), 100), '#3b82f6', firstTime, lastTime, 'ms');
    const cpuPairs = data.filter(d => d.cpu != null).map(d => ({v: d.cpu, ts: d.timestamp}));
    const cpuLabel = 'CPU %' + (cpuModel ? ' <span class="chart-hw-info">'+cpuModel+'</span>' : '');
    if (cpuPairs.length) html += miniChart(cpuLabel, cpuPairs, 100, '#22c55e', firstTime, lastTime, '%');
    const ramPairs = data.filter(d => d.ram_percent != null).map(d => ({v: d.ram_percent, ts: d.timestamp}));
    const ramLabel = 'RAM %' + (ramTotalGB ? ' <span class="chart-hw-info">'+ramTotalGB+' GB total</span>' : '');
    if (ramPairs.length) html += miniChart(ramLabel, ramPairs, 100, '#f59e0b', firstTime, lastTime, '%');
    // Ping chart
    const pingPairs = data.filter(d => d.ping_ms != null).map(d => ({v: d.ping_ms, ts: d.timestamp}));
    if (pingPairs.length) html += miniChart('Ping (ms)', pingPairs, Math.max(...pingPairs.map(p=>p.v), 10), '#a855f7', firstTime, lastTime, 'ms');
    // SSL days chart
    const sslPairs = data.filter(d => d.ssl_days != null).map(d => ({v: d.ssl_days, ts: d.timestamp}));
    if (sslPairs.length) html += miniChart('SSL Expiry (days)', sslPairs, 365, '#06b6d4', firstTime, lastTime, ' days');
    // Bandwidth charts
    const bwRxPairs = data.filter(d => d.bandwidth_rx != null).map(d => ({v: d.bandwidth_rx, ts: d.timestamp}));
    if (bwRxPairs.length) html += miniChart('↓ RX Bandwidth (B/s)', bwRxPairs, Math.max(...bwRxPairs.map(p=>p.v), 1000), '#3b82f6', firstTime, lastTime, 'B/s');
    const bwTxPairs = data.filter(d => d.bandwidth_tx != null).map(d => ({v: d.bandwidth_tx, ts: d.timestamp}));
    if (bwTxPairs.length) html += miniChart('↑ TX Bandwidth (B/s)', bwTxPairs, Math.max(...bwTxPairs.map(p=>p.v), 1000), '#f97316', firstTime, lastTime, 'B/s');

    body.innerHTML = html || '<div class="empty">No metrics data.</div>';
}

function miniChart(title, pairs, maxVal, color, firstTime, lastTime, unit) {
    const bars = pairs.slice(-60).map(p => {
        const h = Math.max(2, (p.v / maxVal) * 60);
        const timeStr = new Date(p.ts * 1000).toLocaleTimeString([], {hour:'2-digit',minute:'2-digit',second:'2-digit'});
        return '<div class="chart-bar" style="height:'+h+'px;background:'+color+';opacity:0.7" ' +
            'data-tip="'+p.v.toFixed(1)+' '+unit+' @ '+timeStr+'"' +
            'onmouseenter="showChartTip(this)" onmousemove="moveChartTip(event)" onmouseleave="hideChartTip()"></div>';
    }).join('');
    const vals = pairs.map(p=>p.v);
    const avg = (vals.reduce((a,b)=>a+b,0)/vals.length).toFixed(1);
    const min = Math.min(...vals).toFixed(1);
    const max = Math.max(...vals).toFixed(1);
    return '<div class="chart-container">' +
        '<div class="chart-title">'+title+' <span class="chart-stats">Avg: '+avg+' · Min: '+min+' · Max: '+max+' · Samples: '+pairs.length+'</span></div>' +
        '<div class="chart-y-axis"><span>'+maxVal.toFixed(0)+'</span><span>'+(maxVal/2).toFixed(0)+'</span><span>0</span></div>' +
        '<div class="mini-chart">'+bars+'</div>' +
        '<div class="chart-x-axis"><span>'+firstTime+'</span><span>'+lastTime+'</span></div>' +
        '</div>';
}

let chartTipEl = null;
function showChartTip(el) {
    if (!chartTipEl) { chartTipEl = document.createElement('div'); chartTipEl.className = 'chart-tip'; document.body.appendChild(chartTipEl); }
    chartTipEl.textContent = el.getAttribute('data-tip');
    chartTipEl.style.display = 'block';
}
function moveChartTip(e) { if (chartTipEl) { chartTipEl.style.left = (e.clientX + 14) + 'px'; chartTipEl.style.top = (e.clientY - 30) + 'px'; } }
function hideChartTip() { if (chartTipEl) chartTipEl.style.display = 'none'; }

function closeHistoryModal() { document.getElementById('history-modal-overlay').classList.remove('active'); }

// ─── Alerts ────────────────────────────────────────────────────────

const METRIC_DEFAULTS = { cpu: 80, ram: 85, disk: 90, response_ms: 1000 };

async function openServerAlerts(sid, name) {
    document.getElementById('a-server-id').value = sid;
    document.getElementById('server-alerts-title').textContent = '⚡ ' + name + ' — Alerts';
    ['a-cpu-enabled','a-ram-enabled','a-disk-enabled','a-response-enabled'].forEach(id => document.getElementById(id).checked = false);
    document.getElementById('a-cpu-threshold').value = METRIC_DEFAULTS.cpu;
    document.getElementById('a-ram-threshold').value = METRIC_DEFAULTS.ram;
    document.getElementById('a-disk-threshold').value = METRIC_DEFAULTS.disk;
    document.getElementById('a-response-threshold').value = METRIC_DEFAULTS.response_ms;
    const res = await apiFetch('/api/servers/' + sid + '/alerts');
    if (res) {
        const rules = await res.json();
        rules.forEach(r => {
            const metric = r.metric;
            if (metric === 'cpu') { document.getElementById('a-cpu-enabled').checked = true; document.getElementById('a-cpu-threshold').value = r.threshold; }
            else if (metric === 'ram') { document.getElementById('a-ram-enabled').checked = true; document.getElementById('a-ram-threshold').value = r.threshold; }
            else if (metric === 'disk') { document.getElementById('a-disk-enabled').checked = true; document.getElementById('a-disk-threshold').value = r.threshold; }
            else if (metric === 'response_ms') { document.getElementById('a-response-enabled').checked = true; document.getElementById('a-response-threshold').value = r.threshold; }
        });
    }
    document.getElementById('alert-modal-overlay').classList.add('active');
}
function closeAlertModal() { document.getElementById('alert-modal-overlay').classList.remove('active'); }

document.getElementById('alert-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const sid = Number(document.getElementById('a-server-id').value);
    const alerts = [];
    if (document.getElementById('a-cpu-enabled').checked) alerts.push({ metric: 'cpu', threshold: Number(document.getElementById('a-cpu-threshold').value), enabled: true });
    if (document.getElementById('a-ram-enabled').checked) alerts.push({ metric: 'ram', threshold: Number(document.getElementById('a-ram-threshold').value), enabled: true });
    if (document.getElementById('a-disk-enabled').checked) alerts.push({ metric: 'disk', threshold: Number(document.getElementById('a-disk-threshold').value), enabled: true });
    if (document.getElementById('a-response-enabled').checked) alerts.push({ metric: 'response_ms', threshold: Number(document.getElementById('a-response-threshold').value), enabled: true });
    const res = await apiFetch('/api/servers/' + sid + '/alerts', { method: 'PUT', headers: {'Content-Type':'application/json'}, body: JSON.stringify({ alerts }) });
    if (!res || !res.ok) { const err = await res?.json().catch(()=>({})); return alert(err.detail || 'Error.'); }
    closeAlertModal();
    if (typeof loadAlertRules === 'function') loadAlertRules();
});

async function loadAlertRules() {
    const res = await apiFetch('/api/alert-rules');
    if (!res) return;
    const rules = await res.json();
    const el = document.getElementById('alert-rules-list');
    if (!rules.length) { el.innerHTML = '<div class="empty">No alert rules. Click ⚡ Alerts on a server card to configure.</div>'; return; }
    el.innerHTML = '<table class="detail-table"><thead><tr><th>Server</th><th>Metric</th><th>Threshold</th><th></th></tr></thead><tbody>'+
        rules.map(r => '<tr><td>'+esc(r.server_name)+'</td><td>'+esc(r.metric)+'</td><td>'+r.threshold+'</td><td><button class="icon-btn danger" onclick="deleteAlertRule('+r.id+')">Del</button></td></tr>').join('')+
        '</tbody></table>';
}

async function loadAlertLog() {
    const res = await apiFetch('/api/alerts?limit=50');
    if (!res) return;
    const alerts = await res.json();
    const el = document.getElementById('alert-log-list');
    if (!alerts.length) { el.innerHTML = '<div class="empty">No alerts yet.</div>'; return; }
    el.innerHTML = alerts.map(a =>
        '<div class="list-item"><div><div class="list-title">'+esc(a.server_name)+'</div><div class="list-sub">'+esc(a.message)+'</div></div><span class="list-sub">'+fmtTime(a.timestamp)+'</span></div>'
    ).join('');
}

async function deleteAlertRule(id) {
    const res = await apiFetch('/api/alert-rules/' + id, { method: 'DELETE' });
    if (!res || !res.ok) return alert('Error.');
    loadAlertRules();
}

// ─── Maintenance Windows ─────────────────────────────────────────────

async function loadMaintenanceWindows() {
    const res = await apiFetch('/api/maintenance-windows');
    if (!res) return;
    const windows = await res.json();
    const el = document.getElementById('maintenance-list');
    if (!windows.length) { el.innerHTML = '<div class="empty">No maintenance windows configured.</div>'; return; }
    const dayNames = ['Mon','Tue','Wed','Thu','Fri','Sat','Sun'];
    el.innerHTML = '<table class="detail-table"><thead><tr><th>Server</th><th>From</th><th>To</th><th>Days</th><th></th></tr></thead><tbody>'+
        windows.map(w => {
            const days = w.days_of_week.split(',').map(d => dayNames[parseInt(d)]).join(', ');
            return '<tr><td>'+esc(w.server_name)+'</td><td>'+String(w.start_hour).padStart(2,'0')+':'+String(w.start_minute).padStart(2,'0')+'</td><td>'+String(w.end_hour).padStart(2,'0')+':'+String(w.end_minute).padStart(2,'0')+'</td><td>'+days+'</td><td><button class="icon-btn danger" onclick="deleteMaintenanceWindow('+w.id+')">Del</button></td></tr>';
        }).join('')+
        '</tbody></table>';
}

function openMaintenanceModal() {
    document.getElementById('maintenance-form').reset();
    // Populate server dropdown
    const sel = document.getElementById('mw-server-id');
    sel.innerHTML = serversCache.map(s => '<option value="'+s.id+'">'+esc(s.name)+'</option>').join('');
    document.getElementById('maintenance-modal-overlay').classList.add('active');
}
function closeMaintenanceModal() { document.getElementById('maintenance-modal-overlay').classList.remove('active'); }

document.getElementById('maintenance-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const payload = {
        server_id: Number(document.getElementById('mw-server-id').value),
        start_hour: Number(document.getElementById('mw-start-hour').value),
        start_minute: Number(document.getElementById('mw-start-minute').value),
        end_hour: Number(document.getElementById('mw-end-hour').value),
        end_minute: Number(document.getElementById('mw-end-minute').value),
        days_of_week: document.getElementById('mw-days').value,
        enabled: true,
    };
    const res = await apiFetch('/api/maintenance-windows', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify(payload) });
    if (!res || !res.ok) { const err = await res?.json().catch(()=>({})); return alert(err.detail || 'Error.'); }
    closeMaintenanceModal(); loadMaintenanceWindows();
});

async function deleteMaintenanceWindow(id) {
    if (!confirm('Delete this maintenance window?')) return;
    const res = await apiFetch('/api/maintenance-windows/' + id, { method: 'DELETE' });
    if (!res || !res.ok) return alert('Error.');
    loadMaintenanceWindows();
}

// ─── Users ─────────────────────────────────────────────────────────

function openUserModal() { document.getElementById('user-form').reset(); document.getElementById('user-modal-overlay').classList.add('active'); }
function closeUserModal() { document.getElementById('user-modal-overlay').classList.remove('active'); }

function openPasswordModal(uid, username) {
    document.getElementById('pw-user-id').value = uid;
    document.getElementById('pw-username').value = username;
    document.getElementById('pw-user-display').value = username;
    document.getElementById('pw-new-password').value = '';
    document.getElementById('password-modal-overlay').classList.add('active');
}
function closePasswordModal() { document.getElementById('password-modal-overlay').classList.remove('active'); }

async function loadUsers() {
    const res = await apiFetch('/api/users');
    if (!res) { document.getElementById('users-list').innerHTML = '<div class="empty">Admin access required.</div>'; return; }
    const users = await res.json();
    const el = document.getElementById('users-list');
    el.innerHTML = '<table class="detail-table"><thead><tr><th>Username</th><th>Role</th><th>Created</th><th></th></tr></thead><tbody>'+
        users.map(u => '<tr><td>'+esc(u.username)+'</td><td>'+esc(u.role)+'</td><td>'+fmtTime(u.created_at)+'</td><td>'+
        '<button class="icon-btn" onclick="openPasswordModal('+u.id+',\''+esc(u.username)+'\')">🔑 Password</button> '+
        (u.username==='admin'?'':'<button class="icon-btn danger" onclick="deleteUser('+u.id+')">Del</button>')+
        '</td></tr>').join('')+
        '</tbody></table>';
}

document.getElementById('user-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const payload = {
        username: document.getElementById('u-username').value.trim(),
        password: document.getElementById('u-password').value,
        role: document.getElementById('u-role').value,
    };
    const res = await apiFetch('/api/users', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify(payload) });
    if (!res || !res.ok) { const err = await res?.json().catch(()=>({})); return alert(err.detail || 'Error.'); }
    closeUserModal(); loadUsers();
});

async function deleteUser(id) {
    if (!confirm('Delete this user?')) return;
    const res = await apiFetch('/api/users/' + id, { method: 'DELETE' });
    if (!res || !res.ok) { const err = await res?.json().catch(()=>({})); return alert(err.detail || 'Error.'); }
    loadUsers();
}

document.getElementById('password-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const uid = document.getElementById('pw-user-id').value;
    const password = document.getElementById('pw-new-password').value;
    const res = await apiFetch('/api/users/' + uid + '/password', { method: 'PUT', headers: {'Content-Type':'application/json'}, body: JSON.stringify({ password }) });
    if (!res || !res.ok) { const err = await res?.json().catch(()=>({})); return alert(err.detail || 'Error.'); }
    closePasswordModal();
    alert('Password updated!');
});

// ─── Init ──────────────────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', async () => {
    if (!getToken()) { location.href = '/login'; return; }
    await loadServers();
    connectWs();
    ['server-modal-overlay','alert-modal-overlay','user-modal-overlay','history-modal-overlay','password-modal-overlay','maintenance-modal-overlay'].forEach(id => {
        const el = document.getElementById(id);
        if (el) el.addEventListener('click', (e) => { if (e.target.id === id) e.target.classList.remove('active'); });
    });
});