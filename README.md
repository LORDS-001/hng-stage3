# HNG Stage 3 — Real-Time Anomaly Detection Engine

A production-grade DDoS and anomaly detection system built alongside Nextcloud.
Monitors HTTP traffic in real time, learns normal patterns, automatically blocks
attackers, and alerts via Slack — with a live dashboard, external log storage,
and a standalone watchdog.

![Tools Running](screenshots/Tools%20Running.png)

---

## Live URLs

| Service | URL |
|---|---|
| **Metrics Dashboard** | http://daniel-detector.duckdns.org:8080 |
| **Server IP** | 44.214.252.145 |
| **Nextcloud** | http://44.214.252.145 (IP only) |
| **GitHub** | https://github.com/LORDS-001/hng-stage3 |

---

## Blog Post

[How I Built a Real-Time DDoS Detection Engine from Scratch](https://lords001.hashnode.dev/how-i-built-a-real-time-ddos-detection-engine-from-scratch)

---

## Language Choice

Built in **Python** because:
- `collections.deque` — perfect O(1) sliding window implementation
- `subprocess` — native iptables integration
- `psutil` — system metrics for dashboard
- `flask` — lightweight dashboard server
- `threading` — concurrent background workers
- `pyyaml` — clean configuration management

---

## Architecture

Internet Traffic
↓
Nginx (reverse proxy + JSON logs)
↓
HNG-nginx-logs (named Docker volume)
↓
Detector Daemon (runs on HOST — not Docker)
↓              ↓              ↓              ↓
Block IPs      Slack Alerts   Dashboard    External Logs
(iptables)    (rate limited)  (Flask:9000)  (BetterStack)
↑
Standalone Watchdog (separate systemd service)
monitors detector health independently

---

### Why Detector Runs on Host (Not Docker)

The detector deliberately runs outside Docker because:
- iptables rules must be applied at the **host kernel level**
- Docker containers cannot modify the host firewall
- Host-level detector protects ALL services — not just one container
- If Docker crashes, detector keeps running and protecting the server

---

### Repository Structure

```
hng-stage3/
├── detector/
│   ├── main.py           ← ties all components together
│   ├── monitor.py        ← tails and parses nginx JSON logs
│   ├── baseline.py       ← rolling 30-min baseline calculation
│   ├── detector.py       ← anomaly detection (z-score + rate)
│   ├── blocker.py        ← iptables ban/unban with backoff
│   ├── unbanner.py       ← auto-unban background thread
│   ├── notifier.py       ← rate-limited Slack alerts
│   ├── dashboard.py      ← live Flask web UI
│   ├── watchdog.py       ← internal health monitor
│   ├── logger.py         ← external log storage (BetterStack)
│   ├── config.yaml       ← all configuration (no secrets)
│   └── requirements.txt
├── standalone-watchdog.py ← independent watchdog service
├── nginx/
│   └── nginx.conf         ← JSON access log configuration
├── docs/
│   └── architecture.png
├── screenshots/
│   ├── Tool-running.png
│   ├── Ban-slack.png
│   ├── Unban-slack.png
│   ├── Global-alert-slack.png
│   ├── Iptables-banned.png
│   ├── Audit-log.png
│   └── Baseline-graph.png
├── docker-compose.yml
└── README.md
```

---

## Separated Concerns Architecture

Each component does exactly one job:

| Component | Responsibility |
|---|---|
| `monitor.py` | Read nginx logs only |
| `baseline.py` | Calculate baseline only |
| `detector.py` | Detect anomalies only |
| `blocker.py` | Block/unblock IPs only |
| `unbanner.py` | Auto-unban only |
| `notifier.py` | Send Slack alerts only |
| `dashboard.py` | Serve web UI only |
| `logger.py` | Send logs externally only |
| `watchdog.py` | Monitor detector health |
| `standalone-watchdog.py` | Independent process monitor |

**Why separated?** If Slack goes down you know it's `notifier.py`.
If bans aren't applying you know it's `blocker.py`. Each layer
can be debugged, replaced, or upgraded independently.

---

## How the Sliding Window Works

Two deque-based windows track request rates in real time.

### Per-IP Window
```python
from collections import deque
import time

ip_windows = {}

def record_request(ip):
    now = time.time()

    if ip not in ip_windows:
        ip_windows[ip] = deque()

    # Add timestamp to RIGHT end
    ip_windows[ip].append(now)

    # Evict timestamps older than 60 seconds from LEFT end
    cutoff = now - 60
    while ip_windows[ip] and ip_windows[ip][0] < cutoff:
        ip_windows[ip].popleft()

    # Rate = requests in window / window size
    return len(ip_windows[ip]) / 60
```

### Global Window
Same structure but tracks ALL requests regardless of source IP.

### Why Deques?
- `append()` → O(1) — add new request instantly
- `popleft()` → O(1) — evict old request instantly
- Much faster than lists for this sliding window pattern

### Eviction Logic
Every new request:
1. Timestamp added to right end
2. Check left end — older than 60 seconds?
3. Yes → remove it (popleft)
4. Repeat until window is clean
5. `len(deque) / 60` = current rate per second

---

## How the Baseline Works

### Window Size
30 minutes of per-second request counts = up to 1,800 data points.

### Recalculation Interval
Every 60 seconds — mean and stddev recalculated and
written to audit log and BetterStack.

### Per-Hour Slots
Traffic varies by time of day. The system maintains
separate data per hour of the day:

```python
hourly_slots = {
    0:  [0.8, 1.1, 0.9],   # midnight traffic
    9:  [4.2, 5.1, 3.8],   # morning rush
    14: [2.8, 3.2, 2.5],   # afternoon
    22: [1.2, 0.9, 1.4],   # evening
}
```

**Priority rule:** If current hour has 10+ samples → use it.
Otherwise fall back to full 30-minute rolling window.

### Floor Value
Minimum baseline of `1.0 req/s` prevents:
- Division by zero
- False positives during very quiet periods
- Oversensitive detection at night

### Baseline Formula
```python
mean   = sum(counts) / len(counts)
stddev = sqrt(sum((x - mean)^2 for x in counts) / len(counts))
```

---

## How Detection Works

An anomaly fires when **either** condition triggers first:

### Condition 1 — Z-Score (Statistical)
```python
zscore = (current_rate - baseline_mean) / baseline_stddev
if zscore > 3.0:
    # ANOMALY DETECTED
```
Measures how many standard deviations above normal.
A z-score > 3.0 means statistically extreme traffic.

### Condition 2 — Rate Multiplier (Volume)
```python
if current_rate > 5.0 * baseline_mean:
    # ANOMALY DETECTED
```
Catches obvious attacks even before enough baseline data exists.

### Error Surge — Auto Threshold Tightening
```python
if ip_error_rate > 3.0 * baseline_error_mean:
    # Tighten thresholds to 70%
    zscore_threshold = 3.0 * 0.7    # becomes 2.1
    rate_threshold   = 5.0 * 0.7    # becomes 3.5
```
When an IP generates excessive 4xx/5xx errors (scanning,
probing), thresholds automatically tighten to catch it faster.

### Per-IP vs Global
- **Per-IP anomaly** → ban the IP + full Slack incident report
- **Global anomaly** → Slack alert only (no single IP to block)

---

## How iptables Blocking Works

### Ban Command
```bash
iptables -I INPUT -s <ip> -j DROP
```
- `-I INPUT` → insert at TOP of input chain (highest priority)
- `-s <ip>` → match traffic from this source IP
- `-j DROP` → silently discard packets (attacker gets no response)

### Unban Command
```bash
iptables -D INPUT -s <ip> -j DROP
```
Removes the rule — traffic flows normally again.

### Backoff Schedule
Each repeated offense gets a longer ban:

| Ban Number | Duration |
|---|---|
| 1st ban | 10 minutes |
| 2nd ban | 30 minutes |
| 3rd ban | 2 hours |
| 4th+ ban | Permanent |

Auto-unbanner runs in background thread checking
every 10 seconds and sends Slack notification on every unban.

---

## Slack Alert System

### Rate Limiting
- Same IP → max 1 full alert per 5 minutes
- Repeated attacks → grouped into summary every 5 minutes
- Global anomaly → max 1 alert per 2 minutes
- Watchdog alerts → always immediate, no rate limiting

### Incident Report Format
Every ban alert includes:
🚨 INCIDENT REPORT
━━━━━━━━━━━━━━━━━━━━━━
Attacker IP:   10.99.99.99
Time:          2026-05-09 01:04:45 UTC
Endpoint:      GET /
Attack Type:   Rate spike (volume attack)
Condition:     rate=2.02 > 2.0x mean=1.00
Current Rate:  2.02 req/s
Baseline:      1.00 req/s
Action Taken:  IP banned for 600s
━━━━━━━━━━━━━━━━━━━━━━
Log Sample:    GET / → 200

### Alert Types
| Alert | Trigger | Rate Limited |
|---|---|---|
| 🚨 Incident Report | IP ban | 5 min per IP |
| 📊 Attack Summary | Repeated same IP | Every 5 mins |
| ⚠️ Global Anomaly | Traffic spike | 2 mins |
| ✅ IP Unbanned | Auto-unban fires | No |
| ⚠️ Log File Stale | No new logs 5 mins | No |
| 🔴 Detector Down | Process stopped | No |
| ✅ Detector Online | Process restarted | No |

---

## Watchdog System

Two layers of health monitoring:

### Layer 1 — Internal Watchdog (watchdog.py)
Runs inside the detector process. Monitors:
- Nginx log file existence
- Log file being updated regularly

### Layer 2 — Standalone Watchdog (standalone-watchdog.py)
Runs as a **completely separate systemd service**.
Monitors using `systemctl is-active hng-detector`.
standalone-watchdog (independent process)
↓ checks every 30 seconds
hng-detector (systemd service)

If detector dies → standalone watchdog immediately alerts Slack.
If detector recovers → standalone watchdog sends recovery alert.

**Key insight:** The standalone watchdog runs independently so
even if the detector completely crashes, the watchdog keeps
running and keeps sending alerts.

---

## External Log Storage

All events sent to **BetterStack (Logtail)** in real time:
- Cannot be deleted if server is compromised
- Automatically analyzed for anomalies
- Retained beyond server lifetime
- Accessible from anywhere

Local audit log also maintained as backup:
[2026-05-09 01:04:45 UTC] BAN | ip=10.99.99.99 | condition=rate=2.02 > 2.0x mean=1.00 | rate=2.02 | baseline_mean=1.0 | duration=600 | endpoint=/ | method=GET
[2026-05-09 01:14:45 UTC] UNBAN | ip=10.99.99.99 | released from ban
[2026-05-09 01:04:45 UTC] GLOBAL_ANOMALY | condition=global rate=2.02 > 2.0x mean=1.00 | rate=2.02 | baseline_mean=1.0
[2026-05-09 01:04:37 UTC] BASELINE | mean=1.0 | stddev=0.58 | samples=3

---

## Setup Instructions (Fresh VPS)

### Prerequisites
- Ubuntu 22.04+ VPS (minimum 2 vCPU, 2GB RAM)
- Docker and Docker Compose installed
- Slack workspace with incoming webhook URL
- BetterStack account (free tier) for external logging

### Step 1 — Clone the Repository
```bash
git clone https://github.com/LORDS-001/hng-stage3.git
cd hng-stage3
```

### Step 2 — Install Python Dependencies on Host
```bash
sudo pip3 install flask requests pyyaml psutil --break-system-packages
```

### Step 3 — Configure the Detector
```bash
cp detector/config.yaml /home/ubuntu/detector-host/config.yaml
nano /home/ubuntu/detector-host/config.yaml
```

Fill in your values:
```yaml
slack:
  webhook_url: "https://hooks.slack.com/services/YOUR/WEBHOOK/URL"

logging:
  logtail_token: "YOUR_BETTERSTACK_TOKEN"

whitelist:
  - "127.0.0.1"
  - "YOUR_SERVER_IP"
  - "YOUR_LOCAL_IP"
```

### Step 4 — Copy Detector Files to Host
```bash
cp -r detector/* /home/ubuntu/detector-host/
```

### Step 5 — Start the Docker Stack
```bash
docker compose up -d
docker compose ps
```

Expected output:
NAME        STATUS
nextcloud   Up
nginx       Up

### Step 6 — Install Detector as systemd Service
```bash
sudo nano /etc/systemd/system/hng-detector.service
```

Paste:
```ini
[Unit]
Description=HNG Anomaly Detection Engine
After=network.target docker.service
Requires=docker.service

[Service]
Type=simple
User=root
WorkingDirectory=/home/ubuntu/detector-host
ExecStart=/usr/bin/python3 -u /home/ubuntu/detector-host/main.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable hng-detector
sudo systemctl start hng-detector
```

### Step 7 — Install Standalone Watchdog Service
```bash
sudo cp standalone-watchdog.py /home/ubuntu/
sudo nano /etc/systemd/system/hng-watchdog.service
```

Paste:
```ini
[Unit]
Description=HNG Detector Watchdog
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/home/ubuntu
ExecStart=/usr/bin/python3 -u /home/ubuntu/standalone-watchdog.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable hng-watchdog
sudo systemctl start hng-watchdog
```

### Step 8 — Add SSH Protection Rule
```bash
sudo iptables -I INPUT 1 -p tcp --dport 22 -j ACCEPT
```
Ensures SSH access is never accidentally blocked by bans.

### Step 9 — Verify Everything is Running
```bash
# Docker services
docker compose ps

# Detector service
sudo systemctl status hng-detector

# Watchdog service
sudo systemctl status hng-watchdog

# Nginx logs flowing
sudo tail -3 /var/lib/docker/volumes/HNG-nginx-logs/_data/hng-access.log

# Audit log
tail -5 /home/ubuntu/detector-host/audit.log
```

### Step 10 — Access the Dashboard
http://YOUR-SERVER-IP:8080

### What a Successful Startup Looks Like
[main] Starting HNG Anomaly Detection Engine...
[main] Version 2.0 — Separated concerns + Watchdog + Rate limiting
[main] Config loaded
[logger] Started external log sender
[notifier] Rate-limited Slack notifier started
[unbanner] Started auto-unbanner thread
[dashboard] Started on port 9000
[watchdog] Started — monitoring detector health
[main] All components started
[main] ┌─────────────────────────────────┐
[main] │  Detection layer:  detector.py  │
[main] │  Alerting layer:   notifier.py  │
[main] │  Response layer:   blocker.py   │
[main] │  Health monitor:   watchdog.py  │
[main] │  External logs:    logger.py    │
[main] └─────────────────────────────────┘
[main] Monitoring logs...
[monitor] Tailing log file: /var/lib/docker/volumes/HNG-nginx-logs/_data/hng-access.log

---

## Configuration Reference

All thresholds in `detector/config.yaml`:

| Key | Default | Description |
|---|---|---|
| `window_seconds` | 60 | Sliding window size in seconds |
| `baseline_window_minutes` | 30 | Rolling baseline window |
| `recalculation_interval` | 60 | Seconds between baseline updates |
| `zscore_threshold` | 3.0 | Z-score anomaly trigger |
| `rate_multiplier_threshold` | 5.0 | Rate multiplier trigger |
| `error_rate_multiplier` | 3.0 | Error surge multiplier |
| `min_baseline_samples` | 10 | Min samples before baseline used |
| `baseline_floor` | 1.0 | Minimum baseline mean |
| `ip_cooldown` | 300 | Seconds between alerts per IP |
| `global_cooldown` | 120 | Seconds between global alerts |
| `summary_interval` | 300 | Grouped summary interval |

---

## Testing the System

### Test Attack Detection
```bash
# Send 300 parallel requests with single fake IP
for i in $(seq 1 300); do
    curl -s --max-time 2 \
    -H "X-Forwarded-For: 10.99.99.99" \
    http://YOUR-SERVER-IP > /dev/null &
done
wait

# Verify ban
sudo iptables -L INPUT -n
tail -5 /home/ubuntu/detector-host/audit.log
```

### Test Watchdog
```bash
# Stop detector
sudo systemctl stop hng-detector

# Wait 35 seconds — check Slack for DETECTOR IS DOWN alert

# Restart detector
sudo systemctl start hng-detector

# Wait 35 seconds — check Slack for DETECTOR IS BACK ONLINE alert
```

### Test Auto-Unban
After triggering a ban, wait 10 minutes.
Check Slack for unban notification and verify:
```bash
sudo iptables -L INPUT -n   # should be empty
```

---

## Screenshots

### Tool Running
![Tools Running](screenshots/Tools%20Running.png)

### Dashboard
![Dashboard](screenshots/Dashboard.png)

### IP Banned in iptables
![Iptables](screenshots/IP%20Banned.png)

### Audit Log
![Audit Log](screenshots/Audit%20Log.png)

### Slack Ban Alert
![Ban Alert](screenshots/Slack%20Alerts.png)

### Slack Unban Alert
![Unban Alert](screenshots/Unban%20Alert.png)

---

## Audit Log Format

Every event is written in structured format:

[timestamp] ACTION ip | condition | rate | baseline | duration

Examples:

[2026-05-07 06:55:41 UTC] BAN 197.211.53.89 | condition=zscore=1.53 > 1.5 | rate=1.48 | baseline_mean=1.00 | duration=600s
[2026-05-07 07:05:47 UTC] UNBAN 197.211.53.89 | released from ban
[2026-05-07 06:56:07 UTC] BASELINE recalculated | mean=2.37 | stddev=0.97 | samples=70
[2026-05-07 06:56:05 UTC] GLOBAL_ANOMALY | condition=global zscore=4.90 > 1.5 | rate=2.55 | baseline_mean=1.00

---

## Configuration Reference

All thresholds are in `detector/config.yaml`:

| Key | Default | Description |
|---|---|---|
| `window_seconds` | 60 | Sliding window size |
| `baseline_window_minutes` | 30 | Rolling baseline window |
| `recalculation_interval` | 60 | Seconds between baseline updates |
| `zscore_threshold` | 3.0 | Z-score trigger threshold |
| `rate_multiplier_threshold` | 5.0 | Rate multiplier trigger |
| `error_rate_multiplier` | 3.0 | Error surge multiplier |
| `min_baseline_samples` | 10 | Minimum samples before baseline is used |
| `baseline_floor` | 1.0 | Minimum baseline mean |

---

## Troubleshooting

| Problem | Solution |
|---|---|
| Dashboard not loading | Check port 9000 is open in AWS Security Group |
| No bans triggering | Lower `zscore_threshold` in config.yaml |
| Slack alerts not arriving | Test webhook with `curl -X POST webhook_url` |
| Locked out of server | Reboot EC2 instance — clears all iptables rules |
| Nginx not writing logs | `docker compose restart nginx` |
| Detector not starting | `sudo journalctl -u hng-detector -n 30` |
| Watchdog not alerting | `sudo journalctl -u hng-watchdog -n 20` |

---

## GitHub Repository
https://github.com/LORDS-001/hng-stage3

## Blog Post
[How I Built a Real-Time DDoS Detection Engine from Scratch](https://lords001.hashnode.dev/how-i-built-a-real-time-ddos-detection-engine-from-scratch)

---

*HNG Internship 14 — DevSecOps Track — Stage 3*
