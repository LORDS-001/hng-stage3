import subprocess
import time
from collections import defaultdict


class IPBlocker:
    """
    Blocks IPs using iptables DROP rules.
    Tracks ban counts per IP for backoff schedule.
    """

    def __init__(self, config):
        # unban_schedule: list of seconds, -1 = permanent
        self.unban_schedule = config['blocking']['unban_schedule']

        # {ip: ban_count} - how many times this IP has been banned
        self.ban_counts = defaultdict(int)

        # {ip: unban_time} - when to unban (-1 = permanent)
        self.banned_ips = {}

    def ban(self, ip):
        """
        Add iptables DROP rule for the IP.
        Returns ban duration in seconds (-1 = permanent).
        """
        # Get ban duration based on history
        ban_count = self.ban_counts[ip]
        if ban_count < len(self.unban_schedule):
            duration = self.unban_schedule[ban_count]
        else:
            duration = -1  # permanent

        self.ban_counts[ip] += 1

        # Add iptables rule
        try:
            subprocess.run(
                ['iptables', '-I', 'INPUT', '-s', ip, '-j', 'DROP'],
                check=True,
                capture_output=True
            )
            print(f"[blocker] Banned {ip} for {duration}s")
        except subprocess.CalledProcessError as e:
            print(f"[blocker] Failed to ban {ip}: {e}")

        # Record ban time
        if duration == -1:
            self.banned_ips[ip] = -1
        else:
            self.banned_ips[ip] = time.time() + duration

        return duration

    def unban(self, ip):
        """Remove iptables DROP rule for the IP."""
        try:
            subprocess.run(
                ['iptables', '-D', 'INPUT', '-s', ip, '-j', 'DROP'],
                check=True,
                capture_output=True
            )
            print(f"[blocker] Unbanned {ip}")
        except subprocess.CalledProcessError as e:
            print(f"[blocker] Failed to unban {ip}: {e}")

        if ip in self.banned_ips:
            del self.banned_ips[ip]

    def get_banned_ips(self):
        """Return dict of currently banned IPs and their unban times."""
        return dict(self.banned_ips)

    def is_banned(self, ip):
        """Check if an IP is currently banned."""
        return ip in self.banned_ips
