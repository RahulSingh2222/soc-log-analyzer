# SOC Log Analyzer

A Python-based log analysis tool with a GUI that mimics basic SIEM functionality. It allows users to upload log files, analyze login activity, and detect potential security threats.

## Features
- Parse custom logs, Linux auth logs, and Windows exported text logs
- Detect failed and successful login attempts
- Identify brute-force attacks
- Detect successful login after repeated failures
- Detect unusual login times
- GUI-based file upload using Tkinter
- Export analysis report to file

## Technologies Used
- Python
- Tkinter (GUI)
- Regex
- Collections

## Supported Logs
- Custom structured logs (.log / .txt)
- Linux authentication logs
- Windows exported text logs

## How to Run
```bash
python analyzer.py
