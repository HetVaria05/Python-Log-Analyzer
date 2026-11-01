"""
log_analyzer.py — Core analysis logic for the Python Log Analyzer.

This module handles:
- Reading and parsing log files
- Counting log levels (INFO, WARNING, ERROR, CRITICAL)
- Extracting IP addresses and detecting suspicious login activity
- Filtering log entries by date range
- Extracting error/critical messages
"""

import re
from collections import Counter
from datetime import datetime


# Regex patterns used throughout the module
LOG_LINE_PATTERN = re.compile(
    r"^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})"  # timestamp
    r"\s+(\w+)"                                      # log level
    r"\s+(.*)"                                        # message
)
IPV4_PATTERN = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")
FAILED_LOGIN_PATTERN = re.compile(
    r"[Ff]ailed\s+(login|password|authentication)",
    re.IGNORECASE,
)
DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

VALID_LOG_LEVELS = {"INFO", "WARNING", "ERROR", "CRITICAL", "DEBUG"}


def read_log_file(filepath):
    """Read a log file and return its lines as a list of strings.

    Raises FileNotFoundError if the file does not exist, and
    ValueError if the file extension is not .txt or .log.
    """
    import os

    if not os.path.exists(filepath):
        raise FileNotFoundError(f"Log file not found: {filepath}")

    _, ext = os.path.splitext(filepath)
    if ext.lower() not in (".txt", ".log"):
        raise ValueError(
            f"Unsupported file format '{ext}'. Only .txt and .log files are supported."
        )

    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
        return f.readlines()


def parse_log_line(line):
    """Parse a single log line into a dict with keys: timestamp, level, message.

    Returns None if the line doesn't match the expected format.
    """
    match = LOG_LINE_PATTERN.match(line.strip())
    if not match:
        return None

    timestamp_str, level, message = match.groups()
    level = level.upper()

    if level not in VALID_LOG_LEVELS:
        return None

    try:
        timestamp = datetime.strptime(timestamp_str, DATE_FORMAT)
    except ValueError:
        return None

    return {
        "timestamp": timestamp,
        "level": level,
        "message": message.strip(),
    }


def parse_all_lines(lines):
    """Parse a list of raw log lines and return a list of parsed dicts.

    Lines that don't match the expected format are silently skipped.
    """
    parsed = []
    for line in lines:
        entry = parse_log_line(line)
        if entry is not None:
            parsed.append(entry)
    return parsed


def count_log_levels(entries):
    """Return a Counter of log levels from parsed entries."""
    return Counter(entry["level"] for entry in entries)


def get_error_messages(entries):
    """Return a list of entries whose level is ERROR or CRITICAL."""
    return [
        entry for entry in entries
        if entry["level"] in ("ERROR", "CRITICAL")
    ]


def extract_ip_addresses(entries):
    """Return a Counter mapping each IPv4 address to the number of log lines it appears in."""
    ip_counter = Counter()
    for entry in entries:
        ips = IPV4_PATTERN.findall(entry["message"])
        for ip in set(ips):  # count each IP once per line
            ip_counter[ip] += 1
    return ip_counter


def find_failed_logins(entries):
    """Return a Counter mapping IP addresses to the number of failed-login lines they appear in."""
    failed = Counter()
    for entry in entries:
        if FAILED_LOGIN_PATTERN.search(entry["message"]):
            ips = IPV4_PATTERN.findall(entry["message"])
            for ip in set(ips):
                failed[ip] += 1
    return failed


def get_suspicious_ips(entries, threshold=5):
    """Return a dict of IPs whose failed-login count meets or exceeds the threshold."""
    failed = find_failed_logins(entries)
    return {ip: count for ip, count in failed.items() if count >= threshold}


def filter_by_date(entries, start_date=None, end_date=None):
    """Filter parsed entries to those within the given date range (inclusive).

    Parameters
    ----------
    start_date : str or None
        Start date in 'YYYY-MM-DD' format. If None, no lower bound.
    end_date : str or None
        End date in 'YYYY-MM-DD' format. If None, no upper bound.
    """
    filtered = entries

    if start_date:
        try:
            start = datetime.strptime(start_date, "%Y-%m-%d")
        except ValueError:
            raise ValueError(f"Invalid start date format: '{start_date}'. Use YYYY-MM-DD.")
        filtered = [e for e in filtered if e["timestamp"] >= start]

    if end_date:
        try:
            # End of the given day
            end = datetime.strptime(end_date, "%Y-%m-%d").replace(
                hour=23, minute=59, second=59
            )
        except ValueError:
            raise ValueError(f"Invalid end date format: '{end_date}'. Use YYYY-MM-DD.")
        filtered = [e for e in filtered if e["timestamp"] <= end]

    return filtered


def analyze(filepath, threshold=5, start_date=None, end_date=None):
    """Run the full analysis pipeline and return a results dict.

    This is the main entry point that other modules call.
    """
    lines = read_log_file(filepath)
    entries = parse_all_lines(lines)

    if start_date or end_date:
        entries = filter_by_date(entries, start_date, end_date)

    level_counts = count_log_levels(entries)
    errors = get_error_messages(entries)
    ip_counts = extract_ip_addresses(entries)
    failed_logins = find_failed_logins(entries)
    suspicious = get_suspicious_ips(entries, threshold)

    return {
        "filepath": filepath,
        "total_entries": len(entries),
        "level_counts": level_counts,
        "errors": errors,
        "ip_counts": ip_counts,
        "failed_logins": failed_logins,
        "suspicious_ips": suspicious,
        "threshold": threshold,
        "start_date": start_date,
        "end_date": end_date,
    }
