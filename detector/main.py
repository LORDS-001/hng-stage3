"""
main.py - Ties all components together.

Separated concerns:
- monitor.py   → reads logs only
- baseline.py  → calculates baseline only
- detector.py  → detects anomalies only
- blocker.py   → blocks IPs only
- unbanner.py  → unbans IPs only
- notifier.py  → sends alerts only (rate limited)
- watchdog.py  → monitors detector health
- logger.py    → external log storage
- dashboard.py → live web UI
"""

import time
import yaml
import os

from monitor import tail_log
from baseline import BaselineTracker
from detector import AnomalyDetector
from blocker import IPBlocker
from unbanner import AutoUnbanner
from notifier import SlackNotifier
from dashboard import Dashboard
from watchdog import Watchdog
from logger import ExternalLogger


def load_config():
    config_path = os.path.join(os.path.dirname(__file__), 'config.yaml')
    with open(config_path, 'r') as f:
        return yaml.safe_load(f)


def main():
    print("[main] Starting HNG Anomaly Detection Engine...")
    print("[main] Version 2.0 — Separated concerns + Watchdog + Rate limiting")

    # ─────────────────────────────────────────
    # LOAD CONFIG
    # ─────────────────────────────────────────
    config = load_config()
    print("[main] Config loaded")

    # ─────────────────────────────────────────
    # INITIALIZE ALL COMPONENTS SEPARATELY
    # ─────────────────────────────────────────

    # Logging layer (external storage)
    ext_logger = ExternalLogger(config)
    ext_logger.start()

    # Detection layer
    baseline_tracker = BaselineTracker(config)
    detector = AnomalyDetector(config)

    # Response layer
    blocker = IPBlocker(config)

    # Alerting layer (rate limited)
    notifier = SlackNotifier(config)

    # Auto-unban
    unbanner = AutoUnbanner(blocker, notifier, ext_logger)
    unbanner.start()

    # Dashboard
    dashboard = Dashboard(config, detector, blocker, baseline_tracker)
    dashboard.start()

    # Watchdog — monitors the detector itself
    watchdog = Watchdog(config)
    watchdog.start()

    # Track recently banned IPs to avoid duplicate bans
    recently_banned = {}
    ban_cooldown = 60

    print("[main] All components started")
    print("[main] ┌─────────────────────────────────┐")
    print("[main] │  Detection layer:  detector.py  │")
    print("[main] │  Alerting layer:   notifier.py  │")
    print("[main] │  Response layer:   blocker.py   │")
    print("[main] │  Health monitor:   watchdog.py  │")
    print("[main] │  External logs:    logger.py    │")
    print("[main] └─────────────────────────────────┘")
    print("[main] Monitoring logs...")

    # ─────────────────────────────────────────
    # MAIN MONITORING LOOP
    # ─────────────────────────────────────────
    for entry in tail_log(config['logging']['access_log']):

        ip = entry['source_ip']

        # ── DETECTION LAYER ──────────────────
        baseline_tracker.record_request(
            is_error=entry.get('is_error', False)
        )
        detector.record(entry)

        # Update watchdog heartbeat
        watchdog.update_heartbeat()

        # Recalculate baseline periodically
        baseline_stats = baseline_tracker.recalculate()
        if baseline_stats:
            ext_logger.log('BASELINE', {
                'mean': round(baseline_stats['effective_mean'], 2),
                'stddev': round(baseline_stats['effective_stddev'], 2),
                'samples': baseline_stats['sample_count']
            })

        baseline = baseline_tracker.get_baseline()

        # Skip whitelisted IPs
        whitelist = config.get('whitelist', [])
        if ip in whitelist:
            continue

        # Skip already banned IPs
        if blocker.is_banned(ip):
            continue

        # Skip recently banned IPs (cooldown)
        if ip in recently_banned:
            if time.time() - recently_banned[ip] < ban_cooldown:
                continue
            else:
                del recently_banned[ip]

        # ── ANOMALY DETECTION ────────────────
        is_anomalous, reason, rate = detector.check_ip(ip, baseline)

        if is_anomalous:
            print(f"[main] ⚠️  ANOMALY: {ip} — {reason}")

            # ── RESPONSE LAYER ───────────────
            try:
                duration = blocker.ban(ip)
                recently_banned[ip] = time.time()

                # ── ALERTING LAYER ───────────
                notifier.send_ban_alert(
                    ip, reason, rate, baseline, duration, entry
                )

                # ── LOGGING LAYER ────────────
                ext_logger.log('BAN', {
                    'ip': ip,
                    'condition': reason,
                    'rate': round(rate, 2),
                    'baseline_mean': round(baseline['mean'], 2),
                    'duration': duration,
                    'endpoint': entry.get('path', 'unknown'),
                    'method': entry.get('method', 'unknown')
                })

            except Exception as e:
                # Response layer failed — alert separately
                print(f"[main] ❌ BLOCKER FAILED for {ip}: {e}")
                notifier.send_watchdog_alert(
                    "❌ BLOCKER FAILED",
                    f"Could not ban `{ip}`\nError: `{e}`\n"
                    f"Detection worked but blocking failed!"
                )

        # ── GLOBAL ANOMALY CHECK ─────────────
        is_global, global_reason, global_rate = detector.check_global(
            baseline
        )

        if is_global:
            print(f"[main] 🌐 GLOBAL ANOMALY: {global_reason}")

            # Alert only — no IP to block
            notifier.send_global_alert(global_reason, global_rate, baseline)

            ext_logger.log('GLOBAL_ANOMALY', {
                'condition': global_reason,
                'rate': round(global_rate, 2),
                'baseline_mean': round(baseline['mean'], 2)
            })


if __name__ == '__main__':
    main()
