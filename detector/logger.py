"""
logger.py - Sends logs to external storage (Logtail/BetterStack).
Logs cannot be deleted even if server is compromised.
Falls back to local file if external service is unavailable.
"""

import time
import json
import requests
import threading
from queue import Queue


class ExternalLogger:
    def __init__(self, config):
        self.local_path = config['logging']['audit_log']
        # Get external logging token from config
        self.logtail_token = config.get('logging', {}).get(
            'logtail_token', None
        )
        self.logtail_url = "https://in.logtail.com"

        # Queue for async sending
        self.queue = Queue()
        self.running = False

    def start(self):
        """Start background log sender thread."""
        self.running = True
        thread = threading.Thread(target=self._run, daemon=True)
        thread.start()
        print("[logger] Started external log sender")

    def _run(self):
        """Background thread that sends queued logs."""
        while self.running:
            try:
                if not self.queue.empty():
                    entry = self.queue.get(timeout=1)
                    self._send_external(entry)
            except Exception:
                pass
            time.sleep(0.1)

    def log(self, action, data):
        """
        Write structured log entry.
        Always writes locally AND sends externally.
        """
        timestamp = time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())

        # Structured log entry
        entry = {
            "timestamp": timestamp,
            "action": action,
            **data
        }

        # Always write locally first
        self._write_local(entry)

        # Queue for external sending
        self.queue.put(entry)

    def _write_local(self, entry):
        """Write to local audit log."""
        line = f"[{entry['timestamp']}] {entry['action']}"
        for key, value in entry.items():
            if key not in ('timestamp', 'action'):
                line += f" | {key}={value}"

        print(f"[audit] {line}")
        with open(self.local_path, 'a') as f:
            f.write(line + "\n")

    def _send_external(self, entry):
        """Send log to Logtail (BetterStack) for external storage."""
        if not self.logtail_token:
            return  # skip if not configured

        try:
            requests.post(
                self.logtail_url,
                json=entry,
                headers={
                    "Authorization": f"Bearer {self.logtail_token}",
                    "Content-Type": "application/json"
                },
                timeout=5
            )
        except Exception as e:
            print(f"[logger] External send failed: {e}")
            # Not critical — local log still has the entry
