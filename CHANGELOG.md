# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [1.4.0] - 2026-04-30

### Added
- **Maintenance Windows** — Mute alerts during scheduled downtime
  - API: `GET/POST /api/maintenance-windows`
  - Set start/end time + days of week per server
- **SSL Certificate Expiry Monitoring** — New check type `ssl`
  - Monitors days until SSL certificate expires
  - Alert threshold for certificates expiring soon
- **Ping/ICMP Checks** — New check type `ping`
  - Uses system `ping` command for latency measurement
- **Docker Container Monitoring** — New check type `docker`
  - Lists running containers with status via Docker socket
- **Service-Specific Health Checks** — Custom HTTP path + expected status code
  - Set `health_path` (e.g., `/api/health`) and `expected_status` (e.g., `200`)
- **Network Bandwidth Monitoring** — Via SSH: tracks RX/TX bytes and calculates bandwidth
  - Reads `/proc/net/dev` to get interface statistics
  - Calculates bandwidth rate (bytes/sec) between checks
- **Database migrations** — Auto-adds new columns on startup for seamless upgrades

## [1.3.0] - 2026-04-30

### Added
- Top processes in alert emails — 🔥 See which process is eating CPU/RAM
- SSH metrics now collect `ps aux --sort=-%cpu` for top 5 processes
- Alert email template shows PID, %CPU, %MEM, and Command
- Helps identify root cause immediately without logging into the server

## [1.2.0] - 2026-03-23

### Added
- Per-server alerts with checkbox UI — ⚡ Alerts button on each server card
- Modal with checkbox + threshold for CPU, RAM, Disk, Response Time
- API: `GET/PUT /api/servers/{sid}/alerts` (bulk save replaces existing rules)
- Default thresholds: CPU 80%, RAM 85%, Disk 90%, Response 1000ms

## [1.1.1] - 2026-03-23

### Added
- Change password from UI — 🔑 Password button in Users tab
- New API endpoint: `PUT /api/users/{uid}/password`
- Admin can change any user's password; users can change their own
- Password validation: minimum 4 characters

### Fixed
- Wider server cards to prevent metric value wrapping (e.g. "31.1 GB")
- Server grid min-width increased from 280px to 340px
- Metric values now have `white-space:nowrap`

## [1.1.0] - 2026-03-23

### Added
- Y-axis labels (scale: max, mid, 0) on history charts
- X-axis labels (timestamps: first → last) on history charts
- Stats summary per chart: Avg, Min, Max, Samples
- Custom tooltips on chart bars: value + unit + timestamp on hover
- Hover brightness effect on chart bars
- CPU model name auto-collected via SSH (`/proc/cpuinfo`)
- CPU model displayed in CPU % chart title
- RAM total displayed in RAM % chart title
- `cpu_model` column in servers table with auto-migration
- API `/api/history/{sid}` now returns `cpu_model` and `ram_total`

### Fixed
- Consistent default password (`netmon2026`) across Docker, Dockerfile, and .env.example
- .env.example restructured with clear sections and comments

### Changed
- README completely rewritten with proper configuration docs, env variables table, SMTP provider list, and API endpoints

## [1.0.0] - 2026-03-22

### Added
- Real-time monitoring dashboard with WebSocket updates
- Multiple check types: Host, HTTP, HTTPS, TCP, SSH
- SSH monitoring with full system metrics (CPU, RAM, Disk, Uptime, Load)
- Token-based authentication with login page
- REST API with full CRUD for server management
- Swagger/OpenAPI documentation at `/docs`
- Health check endpoint at `/api/health`
- Multi-user support with role-based access (admin/user)
- Alerting system with email notifications and thresholds
- History graphs for CPU, RAM, and response time
- Dark theme UI with glassmorphism design
- Responsive layout for mobile devices
- Docker support with Dockerfile and docker-compose.yml
- Systemd service for auto-start on boot
- SQLite database with 7-day history retention
