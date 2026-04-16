from collections import defaultdict
from datetime import datetime
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
import re


# -------------------------------------------------
# FUNCTION: parse_custom_log_line
# USED FOR:
# Parsing your custom sample format like:
# 2026-04-16 08:15:23 FAILED_LOGIN user=rahul ip=192.168.1.10
# -------------------------------------------------
def parse_custom_log_line(line):
    try:
        parts = line.split()

        if len(parts) < 5:
            return None

        timestamp_str = parts[0] + " " + parts[1]
        event = parts[2]
        user = parts[3].split("=", 1)[1]
        ip = parts[4].split("=", 1)[1]

        if event not in ["FAILED_LOGIN", "SUCCESS_LOGIN"]:
            return None

        return {
            "timestamp": datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S"),
            "event": event,
            "user": user,
            "ip": ip
        }
    except Exception:
        return None


# -------------------------------------------------
# FUNCTION: parse_linux_log_line
# USED FOR:
# Parsing Linux auth.log / ssh logs like:
# Apr 16 09:00:00 kali sshd[1234]: Failed password for invalid user test from 172.16.0.2 port 22 ssh2
# Apr 16 09:05:00 kali sshd[1234]: Accepted password for rahul from 192.168.1.10 port 22 ssh2
# -------------------------------------------------
def parse_linux_log_line(line):
    try:
        current_year = datetime.now().year

        failed_pattern = re.search(
            r"^([A-Z][a-z]{2}\s+\d+\s+\d+:\d+:\d+).*Failed password for(?: invalid user)?\s+(\S+)\s+from\s+(\d+\.\d+\.\d+\.\d+)",
            line
        )

        success_pattern = re.search(
            r"^([A-Z][a-z]{2}\s+\d+\s+\d+:\d+:\d+).*Accepted password for\s+(\S+)\s+from\s+(\d+\.\d+\.\d+\.\d+)",
            line
        )

        if failed_pattern:
            timestamp_str = f"{current_year} {failed_pattern.group(1)}"
            return {
                "timestamp": datetime.strptime(timestamp_str, "%Y %b %d %H:%M:%S"),
                "event": "FAILED_LOGIN",
                "user": failed_pattern.group(2),
                "ip": failed_pattern.group(3)
            }

        if success_pattern:
            timestamp_str = f"{current_year} {success_pattern.group(1)}"
            return {
                "timestamp": datetime.strptime(timestamp_str, "%Y %b %d %H:%M:%S"),
                "event": "SUCCESS_LOGIN",
                "user": success_pattern.group(2),
                "ip": success_pattern.group(3)
            }

        return None
    except Exception:
        return None


# -------------------------------------------------
# FUNCTION: parse_windows_blocks
# USED FOR:
# Parsing Windows exported text logs saved as text blocks.
# Example block:
# Date: 16/04/2026
# Time: 08:15:23
# An account failed to log on
# Account Name: Rahul
# Source Network Address: 192.168.1.10
# -------------------------------------------------
def parse_windows_blocks(content):
    logs = []

    # split by blank blocks
    blocks = re.split(r"\n\s*\n", content)

    for block in blocks:
        block_lower = block.lower()

        if (
            "failed to log on" not in block_lower
            and "successfully logged on" not in block_lower
            and "logged on" not in block_lower
        ):
            continue

        event = None
        if "failed to log on" in block_lower:
            event = "FAILED_LOGIN"
        elif "successfully logged on" in block_lower or "logged on" in block_lower:
            event = "SUCCESS_LOGIN"

        if not event:
            continue

        ip_match = re.search(r"Source Network Address:\s*([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)", block, re.IGNORECASE)
        user_match = re.search(r"Account Name:\s*([^\n\r]+)", block, re.IGNORECASE)
        date_match = re.search(r"Date:\s*([^\n\r]+)", block, re.IGNORECASE)
        time_match = re.search(r"Time:\s*([^\n\r]+)", block, re.IGNORECASE)

        ip = ip_match.group(1).strip() if ip_match else "Unknown"
        user = user_match.group(1).strip() if user_match else "Unknown"

        timestamp = datetime.now()

        # Try common Windows date/time formats
        if date_match and time_match:
            date_str = date_match.group(1).strip()
            time_str = time_match.group(1).strip()
            combined = f"{date_str} {time_str}"

            possible_formats = [
                "%d/%m/%Y %H:%M:%S",
                "%m/%d/%Y %H:%M:%S",
                "%d-%m-%Y %H:%M:%S",
                "%Y-%m-%d %H:%M:%S",
            ]

            for fmt in possible_formats:
                try:
                    timestamp = datetime.strptime(combined, fmt)
                    break
                except ValueError:
                    continue

        logs.append({
            "timestamp": timestamp,
            "event": event,
            "user": user,
            "ip": ip
        })

    return logs


# -------------------------------------------------
# FUNCTION: parse_log_file
# USED FOR:
# Main parser that tries:
# 1) custom sample log
# 2) Linux auth log
# 3) Windows exported text log
# -------------------------------------------------
def parse_log_file(filename):
    logs = []

    with open(filename, "r", encoding="utf-8", errors="ignore") as file:
        content = file.read()

    # First try Windows block parsing
    windows_logs = parse_windows_blocks(content)
    if windows_logs:
        logs.extend(windows_logs)

    # Then try line-by-line parsing for custom and Linux logs
    lines = content.splitlines()

    for line in lines:
        line = line.strip()

        if not line:
            continue

        log_entry = parse_custom_log_line(line)

        if log_entry is None:
            log_entry = parse_linux_log_line(line)

        if log_entry is not None:
            logs.append(log_entry)

    return logs


# -------------------------------------------------
# FUNCTION: analyze_logs
# USED FOR:
# Detecting:
# - total failed logins
# - total successful logins
# - brute-force attempts
# - success after repeated failures
# - unusual login times
# -------------------------------------------------
def analyze_logs(logs):
    failed_count = 0
    success_count = 0
    failed_by_ip = defaultdict(int)
    failed_by_user = defaultdict(int)
    alerts = []

    for log in logs:
        if log["event"] == "FAILED_LOGIN":
            failed_count += 1
            failed_by_ip[log["ip"]] += 1
            failed_by_user[log["user"]] += 1

        elif log["event"] == "SUCCESS_LOGIN":
            success_count += 1

    for ip, count in failed_by_ip.items():
        if count > 5:
            alerts.append(f"Possible brute-force attack from IP {ip}")

    for log in logs:
        if log["event"] == "SUCCESS_LOGIN" and failed_by_ip.get(log["ip"], 0) >= 3:
            alerts.append(
                f"Successful login after multiple failed attempts from IP {log['ip']}"
            )

    for log in logs:
        if log["event"] == "SUCCESS_LOGIN":
            hour = log["timestamp"].hour
            if 0 <= hour < 5:
                alerts.append(
                    f"Unusual login time detected for user {log['user']} from IP {log['ip']}"
                )

    return failed_count, success_count, failed_by_ip, failed_by_user, alerts


# -------------------------------------------------
# FUNCTION: generate_report_content
# USED FOR:
# Creating the final report text shown in GUI
# -------------------------------------------------
def generate_report_content(failed_count, success_count, failed_by_ip, failed_by_user, alerts):
    report = []
    report.append("===== LOG ANALYSIS REPORT =====")
    report.append(f"Total Failed Logins: {failed_count}")
    report.append(f"Total Successful Logins: {success_count}")
    report.append("")

    report.append("Failed Logins by IP:")
    if failed_by_ip:
        for ip, count in failed_by_ip.items():
            report.append(f"{ip} -> {count}")
    else:
        report.append("No failed login IPs found.")

    report.append("")
    report.append("Failed Logins by User:")
    if failed_by_user:
        for user, count in failed_by_user.items():
            report.append(f"{user} -> {count}")
    else:
        report.append("No failed login users found.")

    report.append("")
    report.append("Alerts:")
    if alerts:
        for alert in alerts:
            report.append(f"[!] {alert}")
    else:
        report.append("No alerts found.")

    return "\n".join(report)


# -------------------------------------------------
# FUNCTION: browse_file
# USED FOR:
# Opening file picker in GUI
# -------------------------------------------------
def browse_file():
    file_path = filedialog.askopenfilename(
        title="Select Log File",
        filetypes=[("Supported files", "*.log *.txt"), ("All files", "*.*")]
    )
    if file_path:
        file_entry.delete(0, tk.END)
        file_entry.insert(0, file_path)


# -------------------------------------------------
# FUNCTION: analyze_selected_file
# USED FOR:
# Reading chosen file, parsing, analyzing, showing result
# -------------------------------------------------
def analyze_selected_file():
    file_path = file_entry.get().strip()

    if not file_path:
        messagebox.showerror("Error", "Please select a log file first.")
        return

    try:
        logs = parse_log_file(file_path)

        if not logs:
            messagebox.showwarning(
                "Warning",
                "No supported log entries found.\n\nSupported:\n- Custom sample logs\n- Linux auth logs\n- Windows exported text logs"
            )
            return

        failed_count, success_count, failed_by_ip, failed_by_user, alerts = analyze_logs(logs)
        report = generate_report_content(
            failed_count, success_count, failed_by_ip, failed_by_user, alerts
        )

        output_box.delete("1.0", tk.END)
        output_box.tag_config("alert", foreground="#ef4444")
        output_box.tag_config("normal", foreground="#e2e8f0")

        lines = report.split("\n")
        for line in lines:
            if "[!]" in line:
                output_box.insert(tk.END, line + "\n", "alert")
            else:
                output_box.insert(tk.END, line + "\n", "normal")

    except FileNotFoundError:
        messagebox.showerror("Error", "File not found. Please select a valid file.")
    except Exception as e:
        messagebox.showerror("Error", f"Something went wrong:\n{e}")


# -------------------------------------------------
# FUNCTION: save_report
# USED FOR:
# Saving result to .txt file
# -------------------------------------------------
def save_report():
    report_text = output_box.get("1.0", tk.END).strip()

    if not report_text:
        messagebox.showwarning("Warning", "No report available to save.")
        return

    file_path = filedialog.asksaveasfilename(
        defaultextension=".txt",
        filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
        title="Save Report As"
    )

    if file_path:
        with open(file_path, "w", encoding="utf-8") as file:
            file.write(report_text)
        messagebox.showinfo("Success", "Report saved successfully.")


# -------------------------------------------------
# FUNCTION: clear_all
# USED FOR:
# Clearing selected file path and output area
# -------------------------------------------------
def clear_all():
    file_entry.delete(0, tk.END)
    output_box.delete("1.0", tk.END)


# ==========================
# TKINTER GUI STARTS HERE
# ==========================
root = tk.Tk()
root.title("SOC Log Analyzer")
root.geometry("900x700")
root.configure(bg="#0f172a")
root.resizable(False, False)

title_label = tk.Label(
    root,
    text="SOC Log Analyzer",
    font=("Arial", 22, "bold"),
    bg="#0f172a",
    fg="#38bdf8"
)
title_label.pack(pady=15)

info_label = tk.Label(
    root,
    text="Supports: Custom logs, Linux auth logs, Windows exported text logs (.txt/.log)",
    font=("Arial", 10),
    bg="#0f172a",
    fg="#cbd5e1"
)
info_label.pack()

file_frame = tk.Frame(root, bg="#0f172a")
file_frame.pack(pady=12)

file_label = tk.Label(
    file_frame,
    text="Select Log File:",
    font=("Arial", 12),
    bg="#0f172a",
    fg="white"
)
file_label.grid(row=0, column=0, padx=5)

file_entry = tk.Entry(
    file_frame,
    width=60,
    font=("Arial", 11),
    bg="#1e293b",
    fg="white",
    insertbackground="white"
)
file_entry.grid(row=0, column=1, padx=5)

browse_button = tk.Button(
    file_frame,
    text="Browse",
    command=browse_file,
    bg="#22c55e",
    fg="white",
    width=10,
    font=("Arial", 10, "bold")
)
browse_button.grid(row=0, column=2, padx=5)

analyze_button = tk.Button(
    root,
    text="Analyze Logs",
    command=analyze_selected_file,
    font=("Arial", 12, "bold"),
    bg="#3b82f6",
    fg="white",
    width=20
)
analyze_button.pack(pady=10)

output_box = scrolledtext.ScrolledText(
    root,
    width=100,
    height=25,
    font=("Courier New", 10),
    bg="#020617",
    fg="#e2e8f0",
    insertbackground="white"
)
output_box.pack(padx=10, pady=10)

button_frame = tk.Frame(root, bg="#0f172a")
button_frame.pack(pady=10)

save_button = tk.Button(
    button_frame,
    text="Save Report",
    command=save_report,
    bg="#22c55e",
    fg="white",
    width=15,
    font=("Arial", 10, "bold")
)
save_button.grid(row=0, column=0, padx=10)

clear_button = tk.Button(
    button_frame,
    text="Clear",
    command=clear_all,
    bg="#ef4444",
    fg="white",
    width=15,
    font=("Arial", 10, "bold")
)
clear_button.grid(row=0, column=1, padx=10)

root.mainloop()