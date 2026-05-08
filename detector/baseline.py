import time
import math
from collections import deque, defaultdict


class BaselineTracker:
    """
    Tracks rolling baseline of traffic.

    Uses a 30-minute rolling window of per-second counts.
    Recalculates mean and stddev every 60 seconds.
    Maintains per-hour slots and prefers current hour
    when it has enough data.
    """

    def __init__(self, config):
        self.window_minutes = config['detection']['baseline_window_minutes']
        self.recalc_interval = config['detection']['recalculation_interval']
        self.min_samples = config['detection']['min_baseline_samples']
        self.floor = config['detection']['baseline_floor']

        # Rolling window of (timestamp, count) tuples
        # Stores per-second request counts
        self.window = deque()

        # Per-hour slots: {hour: [counts]}
        self.hourly_slots = defaultdict(list)

        # Current baseline values
        self.effective_mean = self.floor
        self.effective_stddev = 0.0

        # Error rate baseline
        self.error_mean = 0.0
        self.error_stddev = 0.0

        # Per-second counters
        self.current_second = int(time.time())
        self.current_count = 0
        self.current_errors = 0

        # Error window
        self.error_window = deque()

        self.last_recalc = time.time()

    def record_request(self, is_error=False):
        """Record a single request."""
        now = int(time.time())

        if now != self.current_second:
            # Save completed second
            self._flush_second()
            self.current_second = now
            self.current_count = 0
            self.current_errors = 0

        self.current_count += 1
        if is_error:
            self.current_errors += 1

    def _flush_second(self):
        """Save the current second's count to the window."""
        ts = self.current_second
        count = self.current_count
        errors = self.current_errors

        # Add to rolling window
        self.window.append((ts, count))
        self.error_window.append((ts, errors))

        # Add to hourly slot
        hour = time.localtime(ts).tm_hour
        self.hourly_slots[hour].append(count)

        # Evict old entries outside 30-minute window
        cutoff = ts - (self.window_minutes * 60)
        while self.window and self.window[0][0] < cutoff:
            self.window.popleft()
        while self.error_window and self.error_window[0][0] < cutoff:
            self.error_window.popleft()

    def recalculate(self):
        """
        Recalculate mean and stddev from rolling window.
        Prefers current hour's data if it has enough samples.
        Called every 60 seconds.
        """
        now = time.time()
        if now - self.last_recalc < self.recalc_interval:
            return

        self.last_recalc = now

        # Try current hour first
        current_hour = time.localtime().tm_hour
        hourly_data = self.hourly_slots.get(current_hour, [])

        if len(hourly_data) >= self.min_samples:
            counts = hourly_data
        else:
            # Fall back to full rolling window
            counts = [c for _, c in self.window]

        if len(counts) < self.min_samples:
            # Not enough data yet - use floor
            self.effective_mean = self.floor
            self.effective_stddev = 0.0
        else:
            self.effective_mean = max(self.floor, _mean(counts))
            self.effective_stddev = _stddev(counts, self.effective_mean)

        # Recalculate error baseline
        error_counts = [c for _, c in self.error_window]
        if len(error_counts) >= self.min_samples:
            self.error_mean = max(0.0, _mean(error_counts))
            self.error_stddev = _stddev(error_counts, self.error_mean)

        return {
            'effective_mean': self.effective_mean,
            'effective_stddev': self.effective_stddev,
            'error_mean': self.error_mean,
            'sample_count': len(counts),
            'timestamp': now,
        }

    def get_baseline(self):
        """Return current baseline values."""
        return {
            'mean': self.effective_mean,
            'stddev': self.effective_stddev,
            'error_mean': self.error_mean,
            'error_stddev': self.error_stddev,
        }


def _mean(data):
    """Calculate arithmetic mean."""
    if not data:
        return 0.0
    return sum(data) / len(data)


def _stddev(data, mean=None):
    """Calculate standard deviation."""
    if len(data) < 2:
        return 0.0
    if mean is None:
        mean = _mean(data)
    variance = sum((x - mean) ** 2 for x in data) / len(data)
    return math.sqrt(variance)
