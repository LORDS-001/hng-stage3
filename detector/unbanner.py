import time
import threading


class AutoUnbanner:
    """
    Automatically unbans IPs on a backoff schedule.
    Runs in a background thread checking every 10 seconds.
    Sends Slack notification on every unban.
    """

    def __init__(self, blocker, notifier, audit_logger):
        self.blocker = blocker
        self.notifier = notifier
        self.audit_logger = audit_logger
        self.running = False

    def start(self):
        """Start the unbanner background thread."""
        self.running = True
        thread = threading.Thread(target=self._run, daemon=True)
        thread.start()
        print("[unbanner] Started auto-unbanner thread")

    def _run(self):
        """Main unbanner loop - checks every 10 seconds."""
        while self.running:
            try:
                self._check_bans()
            except Exception as e:
                print(f"[unbanner] Error: {e}")
            time.sleep(10)

    def _check_bans(self):
        """Check all banned IPs and unban expired ones."""
        now = time.time()
        to_unban = []

        for ip, unban_time in self.blocker.get_banned_ips().items():
            # -1 means permanent ban
            if unban_time == -1:
                continue

            if now >= unban_time:
                to_unban.append(ip)

        for ip in to_unban:
            self.blocker.unban(ip)

            # Send Slack notification
            self.notifier.send_unban_alert(ip)

            # Write audit log
            self.audit_logger.log_unban(ip)
