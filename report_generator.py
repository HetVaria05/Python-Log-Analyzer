"""
report_generator.py — Report output for the Python Log Analyzer.

Generates:
- A formatted text report printed to the console and saved to a file.
- A CSV export of the analysis results.
"""

import csv
import os
from datetime import datetime


def _separator(char="=", width=60):
    return char * width


def generate_text_report(results, output_dir="reports"):
    """Build a human-readable text report and save it to a file.

    Returns the report as a string so it can also be printed.
    """
    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = os.path.join(output_dir, f"report_{timestamp}.txt")

    lines = []

    lines.append(_separator())
    lines.append("       PYTHON LOG ANALYZER — REPORT")
    lines.append(_separator())
    lines.append(f"  Generated : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"  Log file  : {results['filepath']}")

    if results.get("start_date") or results.get("end_date"):
        date_range = f"{results.get('start_date', 'beginning')} → {results.get('end_date', 'end')}"
        lines.append(f"  Date range: {date_range}")

    lines.append(_separator())

    # --- Summary ---
    lines.append("")
    lines.append("  LOG LEVEL SUMMARY")
    lines.append(_separator("-"))
    lines.append(f"  Total entries analysed: {results['total_entries']}")
    lines.append("")

    level_order = ["INFO", "WARNING", "ERROR", "CRITICAL", "DEBUG"]
    counts = results["level_counts"]
    for level in level_order:
        count = counts.get(level, 0)
        if count:
            bar = "█" * min(count, 40)
            lines.append(f"  {level:<10} {count:>5}  {bar}")

    # --- Errors ---
    errors = results.get("errors", [])
    if errors:
        lines.append("")
        lines.append("  ERROR & CRITICAL MESSAGES")
        lines.append(_separator("-"))
        for entry in errors:
            ts = entry["timestamp"].strftime("%Y-%m-%d %H:%M:%S")
            lines.append(f"  [{ts}] {entry['level']}: {entry['message']}")
    else:
        lines.append("")
        lines.append("  No ERROR or CRITICAL messages found.")

    # --- IP addresses ---
    ip_counts = results.get("ip_counts", {})
    if ip_counts:
        lines.append("")
        lines.append("  IP ADDRESS ACTIVITY")
        lines.append(_separator("-"))
        for ip, count in ip_counts.most_common(20):
            lines.append(f"  {ip:<18} {count:>4} occurrences")

    # --- Failed logins ---
    failed = results.get("failed_logins", {})
    if failed:
        lines.append("")
        lines.append("  FAILED LOGIN ATTEMPTS BY IP")
        lines.append(_separator("-"))
        for ip, count in failed.most_common(20):
            lines.append(f"  {ip:<18} {count:>4} failed attempts")

    # --- Suspicious IPs ---
    suspicious = results.get("suspicious_ips", {})
    lines.append("")
    if suspicious:
        lines.append(f"  ⚠  SUSPICIOUS IPs (threshold ≥ {results['threshold']})")
        lines.append(_separator("-"))
        for ip, count in sorted(suspicious.items(), key=lambda x: -x[1]):
            lines.append(f"  {ip:<18} {count:>4} failed attempts  *** SUSPICIOUS ***")
    else:
        lines.append(f"  No suspicious IPs detected (threshold ≥ {results['threshold']}).")

    lines.append("")
    lines.append(_separator())
    lines.append("  End of report")
    lines.append(_separator())

    report_text = "\n".join(lines)

    with open(filename, "w", encoding="utf-8") as f:
        f.write(report_text)

    return report_text, filename


def export_to_csv(results, output_dir="reports"):
    """Export key analysis data to CSV files inside output_dir.

    Creates two CSV files:
      - log_levels_<timestamp>.csv
      - ip_analysis_<timestamp>.csv

    Returns a list of the file paths created.
    """
    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    created_files = []

    # --- Log levels CSV ---
    levels_file = os.path.join(output_dir, f"log_levels_{timestamp}.csv")
    with open(levels_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Log Level", "Count"])
        for level in ["INFO", "WARNING", "ERROR", "CRITICAL", "DEBUG"]:
            count = results["level_counts"].get(level, 0)
            if count:
                writer.writerow([level, count])
        writer.writerow(["TOTAL", results["total_entries"]])
    created_files.append(levels_file)

    # --- IP analysis CSV ---
    ip_file = os.path.join(output_dir, f"ip_analysis_{timestamp}.csv")
    with open(ip_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["IP Address", "Total Appearances", "Failed Logins", "Suspicious"])

        all_ips = set(results["ip_counts"].keys()) | set(results["failed_logins"].keys())
        for ip in sorted(all_ips):
            total = results["ip_counts"].get(ip, 0)
            failed = results["failed_logins"].get(ip, 0)
            sus = "YES" if ip in results.get("suspicious_ips", {}) else ""
            writer.writerow([ip, total, failed, sus])
    created_files.append(ip_file)

    return created_files
