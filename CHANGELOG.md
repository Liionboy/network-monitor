# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

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
