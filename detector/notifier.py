"""
notifier.py - Slack alerts with rate limiting and incident reports.

Rate limiting:
- Same IP: max 1 alert per 5 minutes
- Global anomaly: max 1 alert per 2 minutes
- Summary: grouped alerts sent every 5 minutes

Incident report format:
- Attacker IP
- Time of event
- Endpoint attacked
- Type of attack
- Action taken
- Log sample
"""

import time
import requests
import threading
from collections import defaultdict


class SlackNotifier:
    def __init__(self, config):
        self.webhook_url = config['slack']['webhook_url']

        # Rate limiting settings
        self.ip_cooldown = 300        # 5 minutes between alerts per IP
        self.global_cooldown = 120    # 2 minutes between global alerts
        self.summary_interval = 300   # send summary every 5 minutes

        # Track last alert times
        self.last_ip_alert = {}       # {ip: timestamp}
        self.last_global_alert = 0

        # Group repeated attacks for summary
        self.pending_alerts = defaultdict(list)  # {ip: [events]}
        self.lock = threading.Lock()

        # Start summary sender
        self._start_summary_thread()

    def _start_summary_thread(self):
        """Send grouped summaries every 5 minutes."""
        def run():
            while True:
                time.sleep(self.summary_interval)
                self._send_summaries()

        thread = threading.Thread(target=run, daemon=True)
        thread.start()
        print("[notifier] Rate-limited Slack notifier started")

    def send_ban_alert(self, ip, condition, rate,
                       baseline, duration, entry=None):
        """
        Send ban alert with rate limiting.
        If same IP alerted recently → queue for summary instead.
        """
        now = time.time()

        with self.lock:
            last_alert = self.last_ip_alert.get(ip, 0)

            if now - last_alert < self.ip_cooldown:
                # Rate limited → add to pending summary
                self.pending_alerts[ip].append({
                    'time': now,
                    'condition': condition,
                    'rate': rate,
                    'duration': duration,
                    'entry': entry
                })
                print(f"[notifier] Rate limited alert for {ip}"
                      f" — queued for summary")
                return

            # Not rate limited → send immediately
            self.last_ip_alert[ip] = now

        self._send(self._format_ban_report(
            ip, condition, rate, baseline, duration, entry
        ))

    def send_unban_alert(self, ip):
        """Send unban alert — no rate limiting on unbans."""
        timestamp = time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())
        message = (
            f"✅ *IP UNBANNED*\n"
            f"━━━━━━━━━━━━━━━━━━━━━━\n"
            f"*IP:* `{ip}`\n"
            f"*Time:* {timestamp}\n"
            f"*Action:* Released from ban — monitoring resumed"
        )
        self._send(message)

    def send_global_alert(self, condition, rate, baseline):
        """Send global anomaly alert with rate limiting."""
        now = time.time()

        if now - self.last_global_alert < self.global_cooldown:
            print("[notifier] Global alert rate limited — skipping")
            return

        self.last_global_alert = now
        timestamp = time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())

        message = (
            f"⚠️ *GLOBAL TRAFFIC ANOMALY*\n"
            f"━━━━━━━━━━━━━━━━━━━━━━\n"
            f"*Time:* {timestamp}\n"
            f"*Condition:* {condition}\n"
            f"*Current Rate:* {rate:.2f} req/s\n"
            f"*Baseline Mean:* {baseline['mean']:.2f} req/s\n"
            f"*Baseline StdDev:* {baseline['stddev']:.2f}\n"
            f"*Action:* Monitoring intensified — no single IP to block"
        )
        self._send(message)

    def send_watchdog_alert(self, title, message):
        """Send watchdog alerts — always immediate, no rate limiting."""
        self._send(f"{title}\n{message}")

    def _format_ban_report(self, ip, condition, rate,
                           baseline, duration, entry=None):
        """Format a proper incident report."""
        timestamp = time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())
        duration_str = "permanent" if duration == -1 else f"{duration}s"

        # Get endpoint from log entry if available
        endpoint = "unknown"
        method = "unknown"
        log_sample = "N/A"

        if entry:
            endpoint = entry.get('path', 'unknown')
            method = entry.get('method', 'unknown')
            status = entry.get('status', 'unknown')
            log_sample = (
                f"`{method} {endpoint} → {status}`"
            )

        # Determine attack type
        if 'zscore' in condition:
            attack_type = "Statistical anomaly (z-score spike)"
        elif 'rate' in condition:
            attack_type = "Rate spike (volume attack)"
        elif 'error_surge' in condition:
            attack_type = "Error surge (scanning/probing)"
        else:
            attack_type = "Anomalous traffic pattern"

        return (
            f"🚨 *INCIDENT REPORT*\n"
            f"━━━━━━━━━━━━━━━━━━━━━━\n"
            f"*Attacker IP:* `{ip}`\n"
            f"*Time:* {timestamp}\n"
            f"*Endpoint:* `{method} {endpoint}`\n"
            f"*Attack Type:* {attack_type}\n"
            f"*Condition:* {condition}\n"
            f"*Current Rate:* {rate:.2f} req/s\n"
            f"*Baseline Mean:* {baseline['mean']:.2f} req/s\n"
            f"*Action Taken:* IP banned for {duration_str}\n"
            f"━━━━━━━━━━━━━━━━━━━━━━\n"
            f"*Log Sample:* {log_sample}"
        )

    def _send_summaries(self):
        """Send grouped summary for IPs with multiple suppressed alerts."""
        with self.lock:
            if not self.pending_alerts:
                return

            for ip, events in self.pending_alerts.items():
                if not events:
                    continue

                count = len(events)
                latest = events[-1]
                timestamp = time.strftime(
                    '%Y-%m-%d %H:%M:%S UTC', time.gmtime()
                )

                message = (
                    f"📊 *ATTACK SUMMARY*\n"
                    f"━━━━━━━━━━━━━━━━━━━━━━\n"
                    f"*Attacker IP:* `{ip}`\n"
                    f"*Time:* {timestamp}\n"
                    f"*Total Events:* {count} alerts suppressed\n"
                    f"*Latest Rate:* {latest['rate']:.2f} req/s\n"
                    f"*Latest Condition:* {latest['condition']}\n"
                    f"*Action:* IP remains banned"
                )
                self._send(message)

            self.pending_alerts.clear()

    def _send(self, message):
        """Send a message to Slack webhook."""
        if not self.webhook_url or 'YOUR' in self.webhook_url:
            print(f"[notifier] Slack not configured: {message[:50]}")
            return

        try:
            response = requests.post(
                self.webhook_url,
                json={"text": message},
                timeout=5
            )
            if response.status_code != 200:
                print(f"[notifier] Slack error: {response.status_code}")
        except requests.RequestException as e:
            print(f"[notifier] Failed to send: {e}")
