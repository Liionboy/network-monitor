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
        }
        return '<div class="server-card '+(s.online?'online':'offline')+'">'+
            '<div class="card-header"><div><div class="server-name">'+esc(s.name)+'</div><div class="server-host">'+esc(s.host)+'</div></div>'+
            '<div class="badge '+(s.online?'ok':'bad')+'">'+(s.online?'ONLINE':'OFFLINE')+'</div></div>'+
            m+'<div class="detail-row"><span>Check</span><span>'+esc(s.check_type.toUpperCase())+'</span></div>'+
            '<div class="detail-row"><span>Latency</span><span>'+(s.response_ms?s.response_ms+' ms':'—')+'</span></div>'+
            '<div class="detail-row"><span>Detail</span><span>'+esc(s.detail||'-')+'</span></div>'+
            '<div class="card-footer"><button class="icon-btn" onclick="openHistory('+s.id+',\''+esc(s.name)+'\')">History</button></div></div>';
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
    document.getElementById('f-enabled').checked = !!s.enabled;
    toggleCheckFields();
    document.getElementById('server-modal-overlay').classList.add('active');
}

function toggleCheckFields() {
    const t = document.getElementById('f-check-type').value;
    document.getElementById('port-wrap').classList.toggle('hidden', t !== 'tcp' && t !== 'ssh');
    document.getElementById('target-wrap').classList.toggle('hidden', t !== 'http' && t !== 'https');
    document.getElementById('ssh-fields').classList.toggle('hidden', t !== 'ssh');
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
    const data = await res.json();
    const body = document.getElementById('history-body');

    if (!data.length) { body.innerHTML = '<div class="empty">No history data yet.</div>'; return; }

    let html = '';
    // Response time chart
    const respData = data.filter(d => d.response_ms != null).map(d => d.response_ms);
    if (respData.length) html += miniChart('Response Time (ms)', respData, Math.max(...respData, 100), '#3b82f6');
    // CPU chart
    const cpuData = data.filter(d => d.cpu != null).map(d => d.cpu);
    if (cpuData.length) html += miniChart('CPU %', cpuData, 100, '#22c55e');
    // RAM chart
    const ramData = data.filter(d => d.ram_percent != null).map(d => d.ram_percent);
    if (ramData.length) html += miniChart('RAM %', ramData, 100, '#f59e0b');

    body.innerHTML = html || '<div class="empty">No metrics data.</div>';
}

function miniChart(title, data, maxVal, color) {
    const bars = data.slice(-60).map(v => {
        const h = Math.max(2, (v / maxVal) * 60);
        return '<div class="chart-bar" style="height:'+h+'px;background:'+color+';opacity:0.7" title="'+v.toFixed(1)+'"></div>';
    }).join('');
    return '<div class="chart-container"><div class="chart-title">'+title+'</div><div class="mini-chart">'+bars+'</div></div>';
}

function closeHistoryModal() { document.getElementById('history-modal-overlay').classList.remove('active'); }

// ─── Alerts ────────────────────────────────────────────────────────

function openAlertModal() {
    const sel = document.getElementById('a-server');
    sel.innerHTML = serversCache.map(s => '<option value="'+s.id+'">'+esc(s.name)+'</option>').join('');
    document.getElementById('alert-form').reset();
    document.getElementById('alert-modal-overlay').classList.add('active');
}
function closeAlertModal() { document.getElementById('alert-modal-overlay').classList.remove('active'); }

async function loadAlertRules() {
    const res = await apiFetch('/api/alert-rules');
    if (!res) return;
    const rules = await res.json();
    const el = document.getElementById('alert-rules-list');
    if (!rules.length) { el.innerHTML = '<div class="empty">No alert rules.</div>'; return; }
    el.innerHTML = '<table class="detail-table"><thead><tr><th>Server</th><th>Metric</th><th>Threshold</th><th>Active</th><th></th></tr></thead><tbody>'+
        rules.map(r => '<tr><td>'+esc(r.server_name)+'</td><td>'+esc(r.metric)+'</td><td>'+r.threshold+'</td><td>'+(r.enabled?'Yes':'No')+'</td><td><button class="icon-btn danger" onclick="deleteAlertRule('+r.id+')">Del</button></td></tr>').join('')+
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

document.getElementById('alert-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const payload = {
        server_id: Number(document.getElementById('a-server').value),
        metric: document.getElementById('a-metric').value,
        threshold: Number(document.getElementById('a-threshold').value),
    };
    const res = await apiFetch('/api/alert-rules', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify(payload) });
    if (!res || !res.ok) return alert('Error.');
    closeAlertModal(); loadAlertRules();
});

async function deleteAlertRule(id) {
    const res = await apiFetch('/api/alert-rules/' + id, { method: 'DELETE' });
    if (!res || !res.ok) return alert('Error.');
    loadAlertRules();
}

// ─── Users ─────────────────────────────────────────────────────────

function openUserModal() { document.getElementById('user-form').reset(); document.getElementById('user-modal-overlay').classList.add('active'); }
function closeUserModal() { document.getElementById('user-modal-overlay').classList.remove('active'); }

async function loadUsers() {
    const res = await apiFetch('/api/users');
    if (!res) { document.getElementById('users-list').innerHTML = '<div class="empty">Admin access required.</div>'; return; }
    const users = await res.json();
    const el = document.getElementById('users-list');
    el.innerHTML = '<table class="detail-table"><thead><tr><th>Username</th><th>Role</th><th>Created</th><th></th></tr></thead><tbody>'+
        users.map(u => '<tr><td>'+esc(u.username)+'</td><td>'+esc(u.role)+'</td><td>'+fmtTime(u.created_at)+'</td><td>'+(u.username==='admin'?'':'<button class="icon-btn danger" onclick="deleteUser('+u.id+')">Del</button>')+'</td></tr>').join('')+
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

// ─── Init ──────────────────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', async () => {
    if (!getToken()) { location.href = '/login'; return; }
    await loadServers();
    connectWs();
    // Close modals on overlay click
    ['server-modal-overlay','alert-modal-overlay','user-modal-overlay','history-modal-overlay'].forEach(id => {
        document.getElementById(id).addEventListener('click', (e) => {
            if (e.target.id === id) e.target.classList.remove('active');
        });
    });
});