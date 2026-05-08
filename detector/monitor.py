import time
import json
import os


def tail_log(filepath):
    """
    Continuously tail a log file line by line.
    Waits for the file to exist before starting.
    Yields parsed log entries as dictionaries.
    """
    while not os.path.exists(filepath):
        print(f"[monitor] Waiting for log file: {filepath}")
        time.sleep(2)

    print(f"[monitor] Tailing log file: {filepath}")

    with open(filepath, 'r') as f:
        f.seek(0, 2)

        while True:
            line = f.readline()
            if not line:
                time.sleep(0.1)
                continue

            line = line.strip()
            if not line:
                continue

            try:
                entry = json.loads(line)
                yield parse_entry(entry)
            except json.JSONDecodeError:
                continue


def parse_entry(raw):
    """
    Parse a raw JSON log entry into a clean dictionary.
    """
    source_ip = raw.get('source_ip', '')

    # Handle comma-separated IPs
    if source_ip and ',' in source_ip:
        source_ip = source_ip.split(',')[0].strip()

    # Default if empty
    if not source_ip or source_ip == '-' or source_ip == '':
        source_ip = '127.0.0.1'

    status = int(raw.get('status', 0))

    return {
        'source_ip': source_ip,
        'timestamp': raw.get('timestamp', ''),
        'method': raw.get('method', '-'),
        'path': raw.get('path', '/'),
        'status': status,
        'response_size': int(raw.get('response_size', 0)),
        'is_error': status >= 400,
    }
