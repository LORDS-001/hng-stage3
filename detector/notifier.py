import requests
import time


class SlackNotifier:
    """
    Sends Slack alerts for bans, unbans, and global anomalies.
    Alerts include condition, rate, baseline, timestamp, duration.
    """

    def __init__(self, config):
        self.webhook_url = config['slack']['webhook_url']

    def _send(self, message):
        """Send a message to Slack webhook."""
        if not self.webhook_url or self.webhook_url == "YOUR_SLACK_WEBHOOK_URL":
            print(f"[notifier] Slack not configured. Message: {message}")
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
            print(f"[notifier] Failed to send Slack alert: {e}")

    def send_ban_alert(self, ip, condition, rate, baseline, duration):
        """Send alert when an IP is banned."""
        duration_str = "permanent" if duration == -1 else f"{duration}s"
        timestamp = time.strftime('%Y-%m-%d %Human:%M:%S UTC', time.gmtime())

        message = (
            f":rotating_light: *IP BANNED*\n"
            f"*IP:* `{ip}`\n"
            f"*Condition:* {condition}\n"
            f"*Current Rate:* {rate:.2f} req/s\n"
            f"*Baseline Mean:* {baseline['mean']:.2f} req/s\n"
            f"*Baseline StdDev:* {baseline['stddev']:.2f}\n"
            f"*Ban Duration:* {duration_str}\n"
            f"*Timestamp:* {timestamp}"
        )
        self._send(message)

    def send_unban_alert(self, ip):
        """Send alert when an IP is unbanned."""
        timestamp = time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())

        message = (
            f":white_check_mark: *IP UNBANNED*\n"
            f"*IP:* `{ip}`\n"
            f"*Timestamp:* {timestamp}"
        )
        self._send(message)

    def send_global_alert(self, condition, rate, baseline):
        """Send alert for global traffic anomaly."""
        timestamp = time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())

        message = (
            f":warning: *GLOBAL TRAFFIC ANOMALY*\n"
            f"*Condition:* {condition}\n"
            f"*Current Global Rate:* {rate:.2f} req/s\n"
            f"*Baseline Mean:* {baseline['mean']:.2f} req/s\n"
            f"*Baseline StdDev:* {baseline['stddev']:.2f}\n"
            f"*Timestamp:* {timestamp}"
        )
        self._send(message)
