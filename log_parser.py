# This script is a small SOC-style log parser.
# It reads authentication log files, extracts failed-login events, and looks for
# repeated activity from the same source IP within a rolling time window.
#
# Why this matters:
# In a real environment, a brute-force attack often looks like multiple failed
# login attempts from one IP inside a short time period. This script turns raw log
# text into a simple security signal we can investigate.

# os helps us work with the operating system, including file paths.
# re gives us Regex support for pattern matching inside log lines.
# sys lets us check whether the terminal supports ANSI colours.
# defaultdict is useful for grouping values by key without writing extra checks.
# datetime and timedelta help us work with timestamps and time windows.
import os
import re
import sys
from collections import defaultdict
from datetime import datetime, timedelta


# Windows terminals sometimes disable ANSI colour escape sequences by default.
# This block tries to enable virtual terminal processing so colour output works.
# If it fails, we silently fall back to plain text because colour is optional.
if os.name == "nt":
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetStdHandle(-11)
        if handle:
            mode = ctypes.c_ulong()
            if kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
                kernel32.SetConsoleMode(handle, mode.value | 0x0004)
    except Exception:
        pass


# These variables store ANSI escape codes for terminal colouring.
# A terminal that supports colours can display alerts more clearly.
# If the output is not a TTY, USE_COLOR will be False and we simply print plain text.
USE_COLOR = sys.stdout.isatty()
RED = "\033[31m"
YELLOW = "\033[33m"
GREEN = "\033[32m"
CYAN = "\033[36m"
BLUE = "\033[34m"
MAGENTA = "\033[35m"
WHITE = "\033[37m"
RESET = "\033[0m"


def colorize(text, color):
    # This helper adds colour only when the terminal supports it.
    # It keeps the script readable in plain terminals and still looks polished in a
    # user-friendly terminal session.
    if USE_COLOR:
        return f"{color}{text}{RESET}"
    return text


def parse_ip_from_line(line):
    # Regex pattern meaning:
    # find the text 'from ' followed by an IPv4 address made of four groups of 1-3 digits.
    # Example match: 'from 10.0.0.5'
    #
    # Why: we need the source IP to group failed attempts by attacker.
    # If we removed this, we would not know which IP generated the activity.
    match = re.search(r"from (\d{1,3}(?:\.\d{1,3}){3})", line)
    if match:
        return match.group(1)
    return None


def parse_timestamp_from_line(line):
    # Regex captures a timestamp shaped like: 'Jan 15 08:15:00'
    # This is the format commonly used in Linux/Unix sshd logs.
    # We then combine it with the current year so Python can build a datetime object.
    match = re.search(r"(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})", line)
    if not match:
        return None

    stamp = match.group(1)
    year = datetime.now().year
    try:
        return datetime.strptime(f"{year} {stamp}", "%Y %b %d %H:%M:%S")
    except ValueError:
        # This prevents the script from crashing if the timestamp format is not
        # exactly what we expected.
        return None


def detect_repeated_failures(log_lines, threshold=5, window_minutes=5):
    # This is the core detection logic for brute-force activity.
    # We use defaultdict(list) so each IP gets its own list of timestamps.
    # That allows us to keep a running history of failed logins by source IP.
    attempts_by_ip = defaultdict(list)

    for line in log_lines:
        # We only care about failed SSH authentication attempts.
        # This avoids counting successful logins or unrelated log messages.
        if "Failed password" not in line:
            continue

        ip = parse_ip_from_line(line)
        timestamp = parse_timestamp_from_line(line)
        if ip and timestamp:
            attempts_by_ip[ip].append(timestamp)

    alerts = []
    for ip, times in attempts_by_ip.items():
        # Sorting is important because the detection is based on a time window.
        # We need a chronological order before we check whether attempts are clustered.
        times.sort()
        start = 0
        for end in range(len(times)):
            # Sliding window logic:
            # Keep the earliest timestamp in the window while removing any attempts
            # older than the allowed time range.
            while times[end] - times[start] > timedelta(minutes=window_minutes):
                start += 1

            count = end - start + 1
            if count >= threshold:
                # Once a threshold is crossed, we record the suspicious period and stop
                # checking additional windows for that same IP.
                alerts.append({
                    "ip": ip,
                    "count": count,
                    "window_start": times[start],
                    "window_end": times[end],
                })
                break

    # Higher counts are displayed first to prioritise the most suspicious events.
    alerts.sort(key=lambda item: item["count"], reverse=True)
    return alerts


def severity_for(count, threshold):
    # This function maps a numeric count to a human-friendly alert level.
    # In SOC work, triage is based on severity so analysts can prioritise action.
    if count >= threshold * 2:
        return colorize("CRITICAL", RED)
    if count >= threshold * 1.5:
        return colorize("HIGH", MAGENTA)
    if count >= threshold:
        return colorize("MEDIUM", YELLOW)
    return colorize("LOW", GREEN)


def trust_score_for(count, threshold):
    # A trust score is not the same as severity.
    # Severity tells you how urgent the case is; trust score reflects how confident
    # we are that the pattern is malicious rather than harmless noise.
    if count >= threshold * 2:
        return colorize("High confidence", GREEN)
    if count >= threshold * 1.5:
        return colorize("Moderate confidence", CYAN)
    if count >= threshold:
        return colorize("Initial suspicion", RED)
    return colorize("Low suspicion", BLUE)


def recommendation_for(count, threshold):
    # This translates the detection result into analyst guidance.
    # In a real SOC, automation should recommend a next step rather than just print a raw number.
    if count >= threshold * 2:
        return (
            colorize("Recommended action: block the IP, review the source host, and escalate to the incident response team.", RED),
            colorize("Immediate response required: isolate the source and notify the incident responder.", MAGENTA),
        )
    if count >= threshold * 1.5:
        return (
            colorize("Recommended action: rate-limit access and investigate whether this is a targeted brute-force attempt.", MAGENTA),
            colorize("Secondary review: verify whether this activity matches expected admin access patterns.", RED),
        )
    if count >= threshold:
        return (
            colorize("Recommended action: monitor the IP closely and verify whether repeated login failures are expected behavior.", "\033[38;5;208m"),
            colorize("Monitoring: continue watching for continued attempts over the next 15 minutes.", GREEN),
        )
    return (
        colorize("Recommended action: continue monitoring; no action needed at this threshold.", GREEN),
        colorize("Status: no active intervention needed at this time.", GREEN),
    )


def print_report(file_path):
    # This function is the main reporting layer.
    # It reads the log file, runs detections, and prints a clear analyst-friendly summary.
    try:
        with open(file_path, 'r', encoding='utf-8', errors='replace') as file_handle:
            # Read all lines so the detection logic can scan the log in one pass.
            logs = file_handle.readlines()

        threshold = 5
        window_minutes = 5
        alerts = detect_repeated_failures(logs, threshold=threshold, window_minutes=window_minutes)

        print()
        print(colorize("=== SOC SECURITY ALERT REPORT ===", CYAN))
        print()
        print(colorize(f"Threshold: {threshold} failed attempts in {window_minutes} minutes", WHITE))
        print()

        if not alerts:
            # False negative risk: if the behavior does not cross the threshold, we do nothing.
            # That is intentional here because the project is built around threshold-based brute-force detection.
            print(colorize("No burst of failed logins exceeded the alert threshold.", GREEN))
            print()
            print(colorize("Recommended action: continue monitoring and review normal login noise for false positives.", GREEN))
        else:
            print(colorize(f"Total suspicious IPs: {len(alerts)}", RED))
            print()
            for alert in alerts:
                sev = severity_for(alert["count"], threshold)
                confidence = trust_score_for(alert["count"], threshold)
                recommendation_line_1, recommendation_line_2 = recommendation_for(alert["count"], threshold)
                ip_label = colorize(f"IP {alert['ip']}", BLUE)
                reason = colorize(
                    f"{alert['count']} failed attempts in {window_minutes} minutes",
                    WHITE,
                )
                range_text = colorize(
                    f"Range: {alert['window_start']} to {alert['window_end']}",
                    YELLOW,
                )
                print(f"{sev} | {confidence} | {ip_label} | {reason} | {range_text}")
                print()
                print(f"  {recommendation_line_1}")
                print(f"  {recommendation_line_2}")
                print()

    except FileNotFoundError:
        # This is a user-facing validation step.
        # It tells the analyst that the path is wrong instead of crashing with a stack trace.
        print("Error: Could not find the file. Please check the path you typed.")


def main():
    # This is the interactive loop for the analyst.
    # It repeatedly asks for a log path until the user exits.
    while True:
        try:
            file = input("Enter file path or press q to quit: ").strip()
        except EOFError:
            # This is an important validation fix.
            # In automated environments or when input is piped, there may be no
            # additional user input available. Instead of crashing, we exit politely.
            print()
            print("No more input detected. Exiting.")
            break

        file = file.strip('"').strip("'")
        file = os.path.expanduser(file)

        if file.lower() in ("q", "quit", "exit"):
            # This gives the user a clean exit path and avoids the script silently ending.
            print()
            print("Goodbye.")
            break

        if not file:
            print("No file path entered. Please try again.")
            continue

        print_report(file)


if __name__ == "__main__":
    # This standard Python pattern ensures main() only runs when the file is executed directly.
    # It prevents the code from running automatically if someone imports it as a module.
    main()
