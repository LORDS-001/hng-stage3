import time
from collections import deque, defaultdict


class AnomalyDetector:
    """
    Detects anomalies using sliding windows and z-score analysis.

    Two deque-based windows:
    - Per-IP: tracks requests per IP in last 60 seconds
    - Global: tracks all requests in last 60 seconds

    Anomaly fired when z-score > 3.0 OR rate > 5x baseline mean.
    Error surge tightens thresholds automatically.
    """

    def __init__(self, config):
        self.window_seconds = config['detection']['window_seconds']
        self.zscore_threshold = config['detection']['zscore_threshold']
        self.rate_multiplier = config['detection']['rate_multiplier_threshold']
        self.error_multiplier = config['detection']['error_rate_multiplier']

        # Per-IP sliding window: {ip: deque of timestamps}
        self.ip_windows = defaultdict(deque)

        # Per-IP error window: {ip: deque of timestamps}
        self.ip_error_windows = defaultdict(deque)

        # Global sliding window: deque of timestamps
        self.global_window = deque()

        # Per-IP request counters for top-10
        self.ip_counters = defaultdict(int)

    def record(self, entry):
        """
        Record a new log entry into sliding windows.
        Evicts entries older than window_seconds.
        """
        now = time.time()
        ip = entry['source_ip']

        # Add to per-IP window
        self.ip_windows[ip].append(now)
        self.ip_counters[ip] += 1

        # Add to global window
        self.global_window.append(now)

        # Track errors per IP
        if entry.get('is_error'):
            self.ip_error_windows[ip].append(now)

        # Evict old entries
        cutoff = now - self.window_seconds
        self._evict(self.ip_windows[ip], cutoff)
        self._evict(self.global_window, cutoff)
        self._evict(self.ip_error_windows[ip], cutoff)

    def _evict(self, window, cutoff):
        """Remove entries older than cutoff from deque."""
        while window and window[0] < cutoff:
            window.popleft()

    def get_ip_rate(self, ip):
        """Get current request rate for an IP (requests per second)."""
        now = time.time()
        cutoff = now - self.window_seconds
        self._evict(self.ip_windows[ip], cutoff)
        return len(self.ip_windows[ip]) / self.window_seconds

    def get_global_rate(self):
        """Get current global request rate (requests per second)."""
        now = time.time()
        cutoff = now - self.window_seconds
        self._evict(self.global_window, cutoff)
        return len(self.global_window) / self.window_seconds

    def get_ip_error_rate(self, ip):
        """Get error rate for an IP."""
        now = time.time()
        cutoff = now - self.window_seconds
        self._evict(self.ip_error_windows[ip], cutoff)
        return len(self.ip_error_windows[ip]) / self.window_seconds

    def check_ip(self, ip, baseline):
        """
        Check if an IP is anomalous.
        Returns (is_anomalous, reason, rate) tuple.
        """
        rate = self.get_ip_rate(ip)
        mean = baseline['mean']
        stddev = baseline['stddev']

        # Check error surge - tighten thresholds
        error_rate = self.get_ip_error_rate(ip)
        error_surge = False
        if baseline['error_mean'] > 0:
            if error_rate > self.error_multiplier * baseline['error_mean']:
                error_surge = True

        # Use tighter thresholds if error surge detected
        zscore_thresh = self.zscore_threshold * 0.7 if error_surge else self.zscore_threshold
        rate_thresh = self.rate_multiplier * 0.7 if error_surge else self.rate_multiplier

        # Z-score check
        if stddev > 0:
            zscore = (rate - mean) / stddev
            if zscore > zscore_thresh:
                reason = f"zscore={zscore:.2f} > {zscore_thresh}"
                if error_surge:
                    reason += " (error_surge)"
                return True, reason, rate

        # Rate multiplier check
        if mean > 0 and rate > rate_thresh * mean:
            reason = f"rate={rate:.2f} > {rate_thresh}x mean={mean:.2f}"
            if error_surge:
                reason += " (error_surge)"
            return True, reason, rate

        return False, None, rate

    def check_global(self, baseline):
        """
        Check if global traffic is anomalous.
        Returns (is_anomalous, reason, rate) tuple.
        """
        rate = self.get_global_rate()
        mean = baseline['mean']
        stddev = baseline['stddev']

        # Z-score check
        if stddev > 0:
            zscore = (rate - mean) / stddev
            if zscore > self.zscore_threshold:
                reason = f"global zscore={zscore:.2f} > {self.zscore_threshold}"
                return True, reason, rate

        # Rate multiplier check
        if mean > 0 and rate > self.rate_multiplier * mean:
            reason = f"global rate={rate:.2f} > {self.rate_multiplier}x mean={mean:.2f}"
            return True, reason, rate

        return False, None, rate

    def get_top_ips(self, n=10):
        """Return top N IPs by request count."""
        sorted_ips = sorted(
            self.ip_counters.items(),
            key=lambda x: x[1],
            reverse=True
        )
        return sorted_ips[:n]
