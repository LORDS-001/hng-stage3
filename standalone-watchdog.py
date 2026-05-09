"""
Standalone watchdog that runs separately from the detector.
Alerts on Slack if detector process dies or logs go stale.
"""
import time
import subprocess
import requests
import yaml
import os

CONFIG_PATH = "/home/ubuntu/detector-host/config.yaml"

def load_config():
    with open(CONFIG_PATH, 'r') as f:
        return yaml.safe_load(f)

def send_slack(webhook_url, message):
    try:
        response = requests.post(
            webhook_url,
            json={"text": message},
            timeout=5
        )
        if response.status_code == 200:
            print(f"[watchdog] Slack alert sent!")
        else:
            print(f"[watchdog] Slack error: {response.status_code}")
    except Exception as e:
        print(f"[watchdog] Slack failed: {e}")

def is_detector_running():
    """Check if hng-detector systemd service is active."""
    result = subprocess.run(
        ['systemctl', 'is-active', 'hng-detector'],
        capture_output=True,
        text=True
    )
    return result.stdout.strip() == 'active'

def is_log_stale(log_path, timeout=300):
    """Check if log file hasn't been updated in timeout seconds."""
    if not os.path.exists(log_path):
        return True, "Log file missing"
    age = time.time() - os.path.getmtime(log_path)
    if age > timeout:
        return True, f"No updates for {int(age/60)} minutes"
    return False, None

def main():
    config = load_config()
    webhook_url = config['slack']['webhook_url']
    log_path = config['logging']['access_log']

    detector_was_running = True
    detector_alerted = False
    log_alerted = False

    print("[watchdog] Started — watching detector health every 30s")

    while True:
        now = time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())
        running = is_detector_running()

        # ── CHECK DETECTOR PROCESS ────────────────
        if not running and detector_was_running:
            print(f"[watchdog] DETECTOR IS DOWN at {now}")
            send_slack(webhook_url,
                f"🔴 *DETECTOR IS DOWN!*\n"
                f"━━━━━━━━━━━━━━━━━━━━━━\n"
                f"*Time:* {now}\n"
                f"*Status:* hng-detector service is not active\n"
                f"*Impact:* Attacks NOT being detected or blocked!\n"
                f"*Fix:* `sudo systemctl restart hng-detector`"
            )
            detector_alerted = True
            detector_was_running = False

        elif running and not detector_was_running:
            print(f"[watchdog] DETECTOR IS BACK at {now}")
            send_slack(webhook_url,
                f"✅ *DETECTOR IS BACK ONLINE*\n"
                f"━━━━━━━━━━━━━━━━━━━━━━\n"
                f"*Time:* {now}\n"
                f"*Status:* hng-detector service is active again\n"
                f"*Impact:* Detection resumed normally"
            )
            detector_alerted = False
            detector_was_running = True
            log_alerted = False

        elif running:
            detector_was_running = True
            detector_alerted = False
            print(f"[watchdog] Detector OK at {now}")

        # ── CHECK LOG FILE (only if detector running) ─
        if running:
            stale, reason = is_log_stale(log_path)
            if stale and not log_alerted:
                print(f"[watchdog] LOG STALE: {reason}")
                send_slack(webhook_url,
                    f"⚠️ *NGINX LOG FILE STALE*\n"
                    f"━━━━━━━━━━━━━━━━━━━━━━\n"
                    f"*Time:* {now}\n"
                    f"*Reason:* {reason}\n"
                    f"*Impact:* Detector running but may miss attacks\n"
                    f"*Check:* `docker compose ps` and nginx status"
                )
                log_alerted = True
            elif not stale:
                log_alerted = False

        time.sleep(30)

if __name__ == '__main__':
    main()
