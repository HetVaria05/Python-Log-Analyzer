"""
test_log_analyzer.py — Unit tests for the Python Log Analyzer.

Run with:  python -m pytest tests/  OR  python -m unittest tests.test_log_analyzer
"""

import os
import sys
import unittest
import tempfile
import shutil
from collections import Counter
from datetime import datetime

# Allow imports from parent directory
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from log_analyzer import (
    read_log_file,
    parse_log_line,
    parse_all_lines,
    count_log_levels,
    get_error_messages,
    extract_ip_addresses,
    find_failed_logins,
    get_suspicious_ips,
    filter_by_date,
    analyze,
)
from report_generator import generate_text_report, export_to_csv


# ── Sample data used across multiple tests ───────────────

SAMPLE_LINES = [
    "2024-07-01 08:00:01 INFO Server started on port 8080\n",
    "2024-07-01 08:03:10 WARNING Disk usage at 78%\n",
    "2024-07-01 08:06:00 ERROR Database query timeout\n",
    "2024-07-01 08:15:00 ERROR Failed login attempt from 203.0.113.50\n",
    "2024-07-01 08:15:30 ERROR Failed login attempt from 203.0.113.50\n",
    "2024-07-01 08:16:00 ERROR Failed login attempt from 203.0.113.50\n",
    "2024-07-01 08:16:30 ERROR Failed login attempt from 203.0.113.50\n",
    "2024-07-01 08:17:00 ERROR Failed login attempt from 203.0.113.50\n",
    "2024-07-01 09:20:00 CRITICAL Out of memory\n",
    "2024-07-02 10:00:00 INFO Hourly health check\n",
]


class TestReadLogFile(unittest.TestCase):
    """Tests for read_log_file()."""

    def test_missing_file_raises(self):
        with self.assertRaises(FileNotFoundError):
            read_log_file("nonexistent_file.log")

    def test_invalid_extension_raises(self):
        tmp = tempfile.NamedTemporaryFile(suffix=".json", delete=False)
        tmp.close()
        try:
            with self.assertRaises(ValueError):
                read_log_file(tmp.name)
        finally:
            os.unlink(tmp.name)

    def test_valid_file_returns_lines(self):
        tmp = tempfile.NamedTemporaryFile(
            suffix=".log", mode="w", delete=False, encoding="utf-8"
        )
        tmp.write("2024-07-01 08:00:00 INFO test\n")
        tmp.close()
        try:
            lines = read_log_file(tmp.name)
            self.assertEqual(len(lines), 1)
        finally:
            os.unlink(tmp.name)


class TestParseLogLine(unittest.TestCase):
    """Tests for parse_log_line()."""

    def test_valid_line(self):
        result = parse_log_line("2024-07-01 08:00:01 INFO Server started")
        self.assertIsNotNone(result)
        self.assertEqual(result["level"], "INFO")
        self.assertEqual(result["message"], "Server started")

    def test_invalid_line_returns_none(self):
        self.assertIsNone(parse_log_line("this is not a log line"))

    def test_empty_line_returns_none(self):
        self.assertIsNone(parse_log_line(""))

    def test_unknown_level_returns_none(self):
        self.assertIsNone(parse_log_line("2024-07-01 08:00:00 TRACE something"))


class TestCountLogLevels(unittest.TestCase):
    """Tests for count_log_levels()."""

    def test_counts(self):
        entries = parse_all_lines(SAMPLE_LINES)
        counts = count_log_levels(entries)
        self.assertEqual(counts["INFO"], 2)
        self.assertEqual(counts["WARNING"], 1)
        self.assertEqual(counts["ERROR"], 6)
        self.assertEqual(counts["CRITICAL"], 1)

    def test_empty_list(self):
        counts = count_log_levels([])
        self.assertEqual(len(counts), 0)


class TestErrorMessages(unittest.TestCase):
    """Tests for get_error_messages()."""

    def test_extracts_errors_and_criticals(self):
        entries = parse_all_lines(SAMPLE_LINES)
        errors = get_error_messages(entries)
        levels = {e["level"] for e in errors}
        self.assertTrue(levels <= {"ERROR", "CRITICAL"})
        self.assertEqual(len(errors), 7)  # 6 ERROR + 1 CRITICAL


class TestIPExtraction(unittest.TestCase):
    """Tests for extract_ip_addresses()."""

    def test_finds_ip(self):
        entries = parse_all_lines(SAMPLE_LINES)
        ips = extract_ip_addresses(entries)
        self.assertIn("203.0.113.50", ips)
        self.assertEqual(ips["203.0.113.50"], 5)

    def test_no_ips(self):
        entries = parse_all_lines(["2024-07-01 08:00:00 INFO No IPs here\n"])
        ips = extract_ip_addresses(entries)
        self.assertEqual(len(ips), 0)


class TestFailedLogins(unittest.TestCase):
    """Tests for find_failed_logins() and get_suspicious_ips()."""

    def test_failed_login_count(self):
        entries = parse_all_lines(SAMPLE_LINES)
        failed = find_failed_logins(entries)
        self.assertEqual(failed["203.0.113.50"], 5)

    def test_suspicious_above_threshold(self):
        entries = parse_all_lines(SAMPLE_LINES)
        suspicious = get_suspicious_ips(entries, threshold=3)
        self.assertIn("203.0.113.50", suspicious)

    def test_suspicious_below_threshold(self):
        entries = parse_all_lines(SAMPLE_LINES)
        suspicious = get_suspicious_ips(entries, threshold=10)
        self.assertNotIn("203.0.113.50", suspicious)


class TestDateFilter(unittest.TestCase):
    """Tests for filter_by_date()."""

    def test_filter_single_day(self):
        entries = parse_all_lines(SAMPLE_LINES)
        filtered = filter_by_date(entries, start_date="2024-07-01", end_date="2024-07-01")
        for e in filtered:
            self.assertEqual(e["timestamp"].date(), datetime(2024, 7, 1).date())

    def test_filter_start_only(self):
        entries = parse_all_lines(SAMPLE_LINES)
        filtered = filter_by_date(entries, start_date="2024-07-02")
        self.assertEqual(len(filtered), 1)

    def test_filter_end_only(self):
        entries = parse_all_lines(SAMPLE_LINES)
        filtered = filter_by_date(entries, end_date="2024-07-01")
        self.assertEqual(len(filtered), 9)

    def test_invalid_date_format_raises(self):
        entries = parse_all_lines(SAMPLE_LINES)
        with self.assertRaises(ValueError):
            filter_by_date(entries, start_date="07-01-2024")


class TestReportGeneration(unittest.TestCase):
    """Tests for report generation (text and CSV)."""

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmp_dir)

    def _make_results(self):
        entries = parse_all_lines(SAMPLE_LINES)
        return {
            "filepath": "test.log",
            "total_entries": len(entries),
            "level_counts": count_log_levels(entries),
            "errors": get_error_messages(entries),
            "ip_counts": extract_ip_addresses(entries),
            "failed_logins": find_failed_logins(entries),
            "suspicious_ips": get_suspicious_ips(entries, 5),
            "threshold": 5,
            "start_date": None,
            "end_date": None,
        }

    def test_text_report_created(self):
        results = self._make_results()
        report_text, path = generate_text_report(results, output_dir=self.tmp_dir)
        self.assertTrue(os.path.exists(path))
        self.assertIn("LOG LEVEL SUMMARY", report_text)

    def test_csv_export_created(self):
        results = self._make_results()
        files = export_to_csv(results, output_dir=self.tmp_dir)
        self.assertEqual(len(files), 2)
        for f in files:
            self.assertTrue(os.path.exists(f))


class TestAnalyzePipeline(unittest.TestCase):
    """Integration test: analyze() with a real temp file."""

    def test_full_pipeline(self):
        tmp = tempfile.NamedTemporaryFile(
            suffix=".log", mode="w", delete=False, encoding="utf-8"
        )
        for line in SAMPLE_LINES:
            tmp.write(line)
        tmp.close()

        try:
            results = analyze(tmp.name, threshold=5)
            self.assertEqual(results["total_entries"], 10)
            self.assertIn("203.0.113.50", results["suspicious_ips"])
        finally:
            os.unlink(tmp.name)


if __name__ == "__main__":
    unittest.main()
