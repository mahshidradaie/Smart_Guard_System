[README_smart-guard-system.md](https://github.com/user-attachments/files/31871436/README_smart-guard-system.md)
# Smart Guard System

A real-time embedded surveillance system built as the final project for the *Real-Time Embedded Systems* course at Sharif University of Technology, Department of Electrical Engineering. The system captures a live camera feed, detects human presence, and reports through a web dashboard, email alerts, and MQTT — starting up automatically with no manual intervention on boot.

## Architecture

The system is made up of three main components:

```
        ┌─────────────────────────────┐
        │        OrangePi board        │
        │  ┌───────────────────────┐  │
        │  │ HTTPS web server (C)   │  │
        │  │ REST API (C + FastAPI  │  │
        │  │   docs layer)          │  │
        │  │ MQTT client (C)        │  │
        │  │ Email sender (C)       │  │
        │  │ System sensors (temp/  │  │
        │  │   memory/CPU) (C)      │  │
        │  └───────────┬───────────┘  │
        │              │               │
        │  ┌───────────▼───────────┐  │
        │  │ Image processing       │  │
        │  │ (person detection,     │  │
        │  │  C/C++, lightweight    │  │
        │  │  model)                │  │
        │  └────────────────────────┘  │
        └──────────────┬───────────────┘
                        │ MQTT (TLS-free local link, auth + QoS 1 + LWT)
                        ▼
              ┌───────────────────┐
              │   Personal computer │
              │  Mosquitto broker   │
              │  (topic monitoring) │
              └────────────────────┘
```

- **OrangePi board (or Linux VM fallback):** hosts the HTTPS web server, REST API, MQTT client, email sender, and system telemetry — all in C.
- **Image processing module:** counts people in the live frame; the only part of the system allowed to use Python (C/C++ preferred).
- **Personal computer:** runs the Mosquitto broker and subscribes to the board's topics.

## Features

### Part 1 — Web server, systemd services & SSL
- HTTPS-only HTML dashboard (HTTP requests redirect to HTTPS) showing the live stream, current person count, and live CPU temperature / free memory / CPU usage (refreshed every 2s)
- Self-signed SSL certificate (CN = student ID)
- systemd services for the web server, image processing, and MQTT client — auto-start on boot, auto-restart on crash, correct dependency ordering (`After`/`Requires`)

### Part 2 — RESTful API & live monitoring
- `GET /api/v1/stream` — MJPEG live stream
- `GET /api/v1/persons` — current person count + timestamp
- `GET /api/v1/telemetry` — CPU temperature, free memory, CPU load
- `POST /api/v1/command` — extensible command execution (e.g. `{"reboot": "cmd"}`)
- `GET /api/v1/history` — last 5 detection records
- All core logic lives in C; a thin FastAPI layer only documents the API via Swagger UI

### Part 3 — Image processing, email & MQTT
- Lightweight person-detection model with bounding boxes, live counter, student ID/date/time overlay, and measured FPS on the output frame
- Email alert (with attached snapshot) on detection, sent from C, debounced to at most one email per 30 seconds
- MQTT client in C publishing to `telemetry/<student_id>/home` and `persons/<student_id>/home` as JSON, with QoS 1 and a Last Will and Testament message

### Part 4 — Extra capabilities
- **Guard mode:** toggled via API; while active, any detection triggers an immediate email with photo and an MQTT message on `alarm/<student_id>/home`
- **Black box history:** detections logged to SQLite with a circular buffer, queryable via API
- **Software watchdog:** detects a stalled image-processing feed (>30s without a new frame), sends a "camera tampering" alert email, and restarts the service
- **Adaptive thermal management:** automatically reduces FPS/resolution when CPU temperature crosses a threshold, and reports the event by email

## Security Requirements

- SSH: public-key or password login only, root login disabled
- MQTT: anonymous access disabled, dedicated authenticated user
- No hardcoded passwords or API keys anywhere in the codebase

## Tech Stack

- **Language:** C for all core logic (image processing may use C/C++, Python only for the FastAPI documentation layer)
- **Web/API:** custom HTTPS server, OpenSSL self-signed certs, thin FastAPI/Swagger layer for docs
- **Messaging:** MQTT via Mosquitto (QoS 1, LWT, authenticated)
- **Storage:** SQLite (circular-buffer detection history)
- **Service management:** systemd (auto-start, auto-restart, dependency ordering)
- **Target hardware:** Orange Pi board, or a Linux VM if the board isn't available

## Suggested Project Structure

```
smart-guard-system/
├── board/
│   ├── webserver/          # HTTPS server + dashboard (C)
│   ├── api/                 # REST endpoints (C) + FastAPI docs layer
│   ├── mqtt-client/         # MQTT client (C)
│   ├── mailer/               # Email sending (C)
│   ├── telemetry/            # CPU temp / memory / load readers (C)
│   ├── watchdog/              # Software watchdog (C)
│   └── services/               # systemd unit files
├── vision/                      # Person-detection module (C/C++ preferred)
├── broker/                       # Mosquitto config (runs on the PC)
├── certs/                         # SSL cert generation scripts
├── db/                             # SQLite schema + init scripts
├── scripts/                         # build/run/test helper scripts
└── report/                           # PDF report, diagrams, experiment logs
```

## Getting Started

```bash
# On the OrangePi (or Linux VM):
cd board/webserver && make && sudo systemctl start smart-guard-web.service

# On the personal computer:
mosquitto -c broker/mosquitto.conf
mosquitto_sub -h <board-ip> -t 'telemetry/<student_id>/home' -u <user> -P <password>
```

Exact build/install/config steps live in each subfolder as the project is implemented.

## Author

Mahshid Radaie
