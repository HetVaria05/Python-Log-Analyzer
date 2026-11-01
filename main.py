"""
main.py — Entry point for the Python Log Analyzer.

Provides a simple interactive menu that lets the user:
 1. Select a log file
 2. Run analyses (level counts, errors, IPs, suspicious activity)
 3. Filter by date
 4. Generate text and CSV reports
"""

import os
import sys

from log_analyzer import (
    analyze,
    read_log_file,
    parse_all_lines,
    count_log_levels,
    get_error_messages,
    extract_ip_addresses,
    find_failed_logins,
    get_suspicious_ips,
    filter_by_date,
)
from report_generator import generate_text_report, export_to_csv


# ── helpers ──────────────────────────────────────────────

def clear_screen():
    os.system("cls" if os.name == "nt" else "clear")


def pause():
    input("\n  Press Enter to continue...")


def print_header(title):
    width = 56
    print()
    print("=" * width)
    print(f"  {title}")
    print("=" * width)


def get_log_files(directory="sample_logs"):
    """List .log and .txt files in the given directory."""
    if not os.path.isdir(directory):
        return []
    return sorted(
        f for f in os.listdir(directory)
        if f.endswith((".log", ".txt"))
    )


# ── menu functions ───────────────────────────────────────

def select_log_file():
    """Let the user pick a log file or type a custom path."""
    print_header("SELECT LOG FILE")
    files = get_log_files()

    if files:
        print("\n  Available sample files:")
        for i, name in enumerate(files, 1):
            print(f"    {i}. sample_logs/{name}")
        print(f"    {len(files) + 1}. Enter a custom file path")
        print()

        choice = input("  Your choice: ").strip()
        try:
            idx = int(choice)
            if 1 <= idx <= len(files):
                return os.path.join("sample_logs", files[idx - 1])
            elif idx == len(files) + 1:
                return input("  Enter file path: ").strip()
        except ValueError:
            pass

        print("  Invalid choice.")
        return None
    else:
        return input("  No sample files found. Enter a file path: ").strip()


def show_level_summary(entries):
    print_header("LOG LEVEL SUMMARY")
    counts = count_log_levels(entries)
    total = len(entries)
    print(f"\n  Total entries: {total}\n")
    for level in ["INFO", "WARNING", "ERROR", "CRITICAL", "DEBUG"]:
        c = counts.get(level, 0)
        if c:
            bar = "█" * min(c, 40)
            print(f"  {level:<10} {c:>5}  {bar}")
    pause()


def show_errors(entries):
    print_header("ERROR & CRITICAL MESSAGES")
    errors = get_error_messages(entries)
    if not errors:
        print("\n  No errors found.")
    else:
        print(f"\n  Found {len(errors)} error-level entries:\n")
        for e in errors:
            ts = e["timestamp"].strftime("%Y-%m-%d %H:%M:%S")
            print(f"  [{ts}] {e['level']}: {e['message']}")
    pause()


def show_ip_analysis(entries):
    print_header("IP ADDRESS ANALYSIS")
    ip_counts = extract_ip_addresses(entries)
    if not ip_counts:
        print("\n  No IP addresses found.")
    else:
        print(f"\n  {'IP Address':<18} {'Occurrences':>12}")
        print("  " + "-" * 32)
        for ip, count in ip_counts.most_common(20):
            print(f"  {ip:<18} {count:>12}")
    pause()


def show_suspicious_ips(entries):
    print_header("SUSPICIOUS IP DETECTION")
    threshold_input = input(
        "  Enter failed-login threshold (default 5): "
    ).strip()
    threshold = int(threshold_input) if threshold_input.isdigit() else 5

    failed = find_failed_logins(entries)
    suspicious = get_suspicious_ips(entries, threshold)

    if failed:
        print(f"\n  Failed login attempts by IP:")
        for ip, count in failed.most_common(20):
            flag = "  *** SUSPICIOUS ***" if ip in suspicious else ""
            print(f"  {ip:<18} {count:>4} attempts{flag}")
    else:
        print("\n  No failed login attempts detected.")

    if suspicious:
        print(f"\n  ⚠  {len(suspicious)} suspicious IP(s) detected "
              f"(threshold ≥ {threshold})")
    else:
        print(f"\n  No suspicious IPs (threshold ≥ {threshold}).")
    pause()


def show_date_filter(entries):
    print_header("DATE FILTER")
    print("  Leave blank to skip a boundary.\n")
    start = input("  Start date (YYYY-MM-DD): ").strip() or None
    end = input("  End date   (YYYY-MM-DD): ").strip() or None

    try:
        filtered = filter_by_date(entries, start, end)
    except ValueError as e:
        print(f"\n  Error: {e}")
        pause()
        return

    print(f"\n  {len(filtered)} entries in the selected range "
          f"(out of {len(entries)} total).")

    counts = count_log_levels(filtered)
    for level in ["INFO", "WARNING", "ERROR", "CRITICAL", "DEBUG"]:
        c = counts.get(level, 0)
        if c:
            print(f"  {level:<10} {c:>5}")
    pause()


def generate_report(filepath, entries):
    print_header("GENERATE REPORT")
    threshold_input = input(
        "  Suspicious-IP threshold (default 5): "
    ).strip()
    threshold = int(threshold_input) if threshold_input.isdigit() else 5

    results = analyze(filepath, threshold=threshold)

    # Text report
    report_text, txt_path = generate_text_report(results)
    print(f"\n  Text report saved to: {txt_path}")

    # CSV export
    csv_files = export_to_csv(results)
    for path in csv_files:
        print(f"  CSV exported to     : {path}")

    print("\n  Preview:\n")
    # Show just the first 30 lines
    for line in report_text.split("\n")[:30]:
        print(line)
    print("  ... (see full report in the file above)")
    pause()


# ── main loop ────────────────────────────────────────────

def main():
    print_header("PYTHON LOG ANALYZER")
    print("  A beginner-friendly log analysis tool.\n")

    filepath = select_log_file()
    if not filepath:
        print("  No file selected. Exiting.")
        return

    try:
        lines = read_log_file(filepath)
    except (FileNotFoundError, ValueError) as e:
        print(f"\n  Error: {e}")
        return

    entries = parse_all_lines(lines)
    if not entries:
        print("  No valid log entries found in the file.")
        return

    print(f"\n  Loaded {len(entries)} log entries from {filepath}.")

    while True:
        print_header("MAIN MENU")
        print("  1. Log Level Summary")
        print("  2. View Errors & Critical Messages")
        print("  3. IP Address Analysis")
        print("  4. Suspicious IP Detection")
        print("  5. Filter by Date")
        print("  6. Generate Full Report (text + CSV)")
        print("  7. Select a Different Log File")
        print("  0. Exit")
        print()

        choice = input("  Your choice: ").strip()

        if choice == "1":
            show_level_summary(entries)
        elif choice == "2":
            show_errors(entries)
        elif choice == "3":
            show_ip_analysis(entries)
        elif choice == "4":
            show_suspicious_ips(entries)
        elif choice == "5":
            show_date_filter(entries)
        elif choice == "6":
            generate_report(filepath, entries)
        elif choice == "7":
            filepath = select_log_file()
            if not filepath:
                print("  No file selected.")
                continue
            try:
                lines = read_log_file(filepath)
            except (FileNotFoundError, ValueError) as e:
                print(f"\n  Error: {e}")
                continue
            entries = parse_all_lines(lines)
            print(f"\n  Loaded {len(entries)} entries from {filepath}.")
        elif choice == "0":
            print("\n  Goodbye!")
            break
        else:
            print("  Invalid choice, please try again.")


if __name__ == "__main__":
    main()
