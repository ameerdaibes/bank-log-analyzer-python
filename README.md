# Bank Log Analyzer — Python

A modular Python application for parsing and analyzing bank database server logs. It converts semi-structured log records into organized security, query, transaction, session, and system-activity reports.

## Features

- Regex-based parsing of structured server-log entries
- Malformed-line handling
- Failed-login reporting by IP and user
- Query activity summaries
- Slow-query detection
- Transaction analysis
- Critical-event reporting
- User activity timelines
- Login/logout session analysis and duration calculation
- Events-per-hour reporting
- General log summaries
- Interactive command-line menu

## Project Structure

```text
bank-log-analyzer-python/
├── main.py
├── cli.py
├── parser.py
├── reports.py
├── bank_server.log
├── README.md
└── .gitignore
```

### `parser.py`
Defines the log-entry representation and parses each line using a compiled regular expression.

### `reports.py`
Contains the `LogAnalyzer` class and report-generation logic.

### `cli.py`
Provides the interactive terminal interface.

### `main.py`
Acts as the application entry point.

## Technologies & Concepts

- Python 3
- Regular expressions
- Object-oriented programming
- Dictionaries and lists
- File I/O
- Exception handling
- Logging
- Datetime processing
- Modular program design
- Command-line applications

## Running the Project

```bash
python3 main.py
```

When prompted, enter the log filename or press Enter to use `bank_server.log`.

## Log Format

```text
[TIMESTAMP] [LOG_LEVEL] [SESSION_ID] [USER] [CLIENT_IP] [MODULE] - MESSAGE
```

## What I Learned

This project expanded the original shell-based analyzer into a modular Python application. It strengthened my understanding of regex parsing, object-oriented design, reusable modules, exception handling, structured data analysis, and interactive command-line software.

## Author

**Ameer Daibes**  
Computer Engineering Student — Birzeit University

[LinkedIn](https://www.linkedin.com/in/ameer-daibes-1510aa207)
