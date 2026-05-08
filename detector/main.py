import time
import threading
import yaml
import os

from monitor import tail_log
from baseline import BaselineTracker
from detector import AnomalyDetector
from blocker import IPBlocker
from unbanner import AutoUnbanner
from notifier import SlackNotifier
from dashboard import Dashboard


class AuditLogger:
    """
    Writes structured audit log entries for every
    ban, unban, and baseline recalculation.
    Format: [timestamp] ACTION ip | condition | rate | baseline | duration
    """

    def __init__(self, log_path):
        self.log_path = log_path
        # Ensure log directory exists
        os.makedirs(os.path.dirname(log_path), exist_ok=True)

    def _write(self, line):
        timestamp = time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())
        entry = f"[{timestamp}] {line}\n"
        print(f"[audit] {entry.strip()}")
        with open(self.log_path, 'a') as f:
            f.write(entry)

    def log_ban(self, ip, condition, rate, baseline, duration):
        duration_str = "permanent" if duration == -1 else f"{duration}s"
        self._write(
            f"BAN {ip} | condition={condition} | "
            f"rate={rate:.2f} | baseline_mean={baseline['mean']:.2f} | "
            f"duration={duration_str}"
        )

    def log_unban(self, ip):
        self._write(f"UNBAN {ip} | released from ban")

    def log_baseline(self, stats):
        self._write(
            f"BASELINE recalculated | "
            f"mean={stats['effective_mean']:.2f} | "
            f"stddev={stats['effective_stddev']:.2f} | "
            f"samples={stats['sample_count']}"
        )

    def log_global_anomaly(self, condition, rate, baseline):
        self._write(
            f"GLOBAL_ANOMALY | condition={condition} | "
            f"rate={rate:.2f} | baseline_mean={baseline['mean']:.2f}"
        )


def load_config():
    """Load configuration from config.yaml."""
    config_path = os.path.join(os.path.dirname(__file__), 'config.yaml')
    with open(config_path, 'r') as f:
        return yaml.safe_load(f)


def main():
    print("[main] Starting HNG Anomaly Detection Engine...")

    # Load config
    config = load_config()
    print("[main] Config loaded")

    # Initialize components
    audit_logger = AuditLogger(config['logging']['audit_log'])
    baseline_tracker = BaselineTracker(config)
    detector = AnomalyDetector(config)
    blocker = IPBlocker(config)
    notifier = SlackNotifier(config)
    unbanner = AutoUnbanner(blocker, notifier, audit_logger)

    # Start dashboard
    dashboard = Dashboard(config, detector, blocker, baseline_tracker)
    dashboard.start()

    # Start auto-unbanner
    unbanner.start()

    # Track recently banned IPs to avoid duplicate bans
    recently_banned = {}
    ban_cooldown = 60  # seconds

    print("[main] All components started. Monitoring logs...")

    # Main monitoring loop
    for entry in tail_log(config['logging']['access_log']):
        ip = entry['source_ip']

        # Record request in both tracker and detector
        baseline_tracker.record_request(is_error=entry.get('is_error', False))
        detector.record(entry)

        # Recalculate baseline periodically
        baseline_stats = baseline_tracker.recalculate()
        if baseline_stats:
            audit_logger.log_baseline(baseline_stats)

        baseline = baseline_tracker.get_baseline()

        # Skip already banned IPs
        if blocker.is_banned(ip):
            continue

        # Skip if recently banned (cooldown period)
        if ip in recently_banned:
            if time.time() - recently_banned[ip] < ban_cooldown:
                continue
            else:
                del recently_banned[ip]

        # Check per-IP anomaly
        is_anomalous, reason, rate = detector.check_ip(ip, baseline)
        if is_anomalous:
            print(f"[main] ANOMALY detected for {ip}: {reason}")

            # Block the IP
            duration = blocker.ban(ip)
            recently_banned[ip] = time.time()

            # Send Slack alert
            notifier.send_ban_alert(ip, reason, rate, baseline, duration)

            # Write audit log
            audit_logger.log_ban(ip, reason, rate, baseline, duration)

        # Check global anomaly
        is_global, global_reason, global_rate = detector.check_global(baseline)
        if is_global:
            print(f"[main] GLOBAL ANOMALY: {global_reason}")

            # Slack alert only for global anomaly
            notifier.send_global_alert(global_reason, global_rate, baseline)

            # Write audit log
            audit_logger.log_global_anomaly(global_reason, global_rate, baseline)


if __name__ == '__main__':
    main()
