# Python Log Analyzer

A command-line application that reads server/application log files, analyses their contents, detects suspicious login activity, and generates reports.

## Features

- **Log Level Analysis** — counts INFO, WARNING, ERROR, and CRITICAL entries
- **Error Detection** — extracts and displays ERROR & CRITICAL messages
- **IP Address Analysis** — identifies all IPv4 addresses and their frequency
- **Suspicious IP Detection** — flags IPs with repeated failed-login attempts (configurable threshold)
- **Date Filtering** — filter log entries by date range
- **Report Generation** — text report + CSV export

## Quick Start

```bash
# No external dependencies — uses Python standard library only
python main.py
```

Follow the interactive menu to select a log file and run analyses.

## Run Tests

```bash
python -m unittest discover -s tests -v
```

## Project Structure

```
python-log-analyzer/
├── main.py               # CLI entry point & interactive menu
├── log_analyzer.py       # Core analysis logic
├── report_generator.py   # Text & CSV report output
├── sample_logs/
│   └── sample.log        # Realistic sample data
├── reports/              # Generated reports (gitignored)
├── tests/
│   └── test_log_analyzer.py
├── PROJECT_EXPLANATION.md  # Beginner-friendly project walkthrough
├── README.md
├── requirements.txt
└── .gitignore
```

## Requirements

- Python 3.6+
- No external packages

## License

MIT
