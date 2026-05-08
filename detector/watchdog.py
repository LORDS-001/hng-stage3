import time
import os
import subprocess
import requests
import yaml
import threading


class Watchdog:
    def __init__(self, config):
        self.webhook_url = config['slack']['webhook_url']
        self.log_path = config['logging']['access_log']
        self.check_interval = 60
        self.log_timeout = 300
        self.last_log_size = 0
        self.last_log_time = time.time()
        self.running = False
        self.alerted = False

    def start(self):
        self.running = True
        thread = threading.Thread(target=self._run, daemon=True)
        thread.start()
        print("[watchdog] Started — monitoring detector health")

    def _run(self):
        while self.running:
            try:
                self._check_log_file()
                self._check_detector_process()
            except Exception as e:
                print(f"[watchdog] Error: {e}")
            time.sleep(self.check_interval)

    def _check_log_file(self):
        if not os.path.exists(self.log_path):
            self._alert(
                "WARNING LOG FILE MISSING",
                f"Nginx log file not found: {self.log_path}\n"
                "Detector cannot read traffic. Check Nginx container."
            )
            return

        current_size = os.path.getsize(self.log_path)
        if current_size != self.last_log_size:
            self.last_log_size = current_size
            self.last_log_time = time.time()
            self.alerted = False
        else:
            silent_for = time.time() - self.last_log_time
            if silent_for > self.log_timeout:
                self._alert(
                    "WARNING LOG FILE STALE",
                    f"No new log entries for {int(silent_for/60)} minutes.\n"
                    "Either no traffic or Nginx stopped writing logs."
                )

    def _check_detector_process(self):
        try:
            result = subprocess.run(
                ['pgrep', '-f', 'main.py'],
                capture_output=True,
                text=True
            )
            if result.returncode != 0:
                self._alert(
                    "DETECTOR PROCESS DOWN",
                    "The detector process is not running!\n"
                    "Attacks are NOT being detected or blocked.\n"
                    "Restart: sudo systemctl restart hng-detector"
                )
        except Exception as e:
            print(f"[watchdog] Process check failed: {e}")

    def update_heartbeat(self):
        self.last_log_time = time.time()
        self.alerted = False

    def _alert(self, title, message):
        if self.alerted:
            return
        self.alerted = True
        timestamp = time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())
        text = f"{title}\nTime: {timestamp}\n{message}"
        try:
            requests.post(
                self.webhook_url,
                json={"text": text},
                timeout=5
            )
            print(f"[watchdog] Alert sent: {title}")
        except Exception as e:
            print(f"[watchdog] Failed to send alert: {e}")
