# This script creates synthetic authentication logs for testing and demonstration.
# It is not a production log generator; it is designed to simulate normal SSH traffic
# plus a few suspicious failed-login bursts that a detection script can recognise.
#
# Why do this?
# Security teams often need realistic test data before they build detection rules.
# This script gives us a controllable way to generate logs that resemble real-world
# brute-force attempts without using live production data.

# os helps us check whether a file already exists so we can create a unique name.
# random lets us vary the traffic pattern so it is not always the same.
# datetime and timedelta let us create realistic times for log entries.
import os
import random
from datetime import datetime, timedelta


def random_ip():
    # Create a random IPv4 address by generating four numbers between 0 and 255.
    # This is useful for simulation, but we do not want private or reserved ranges in
    # the suspicious traffic we later label as attacker behaviour.
    return ".".join(str(random.randint(0, 255)) for _ in range(4))


def random_non_private_ip():
    # We keep generating IPs until we find one that is not in a private or loopback range.
    # This is important because the suspicious sources should look like external traffic.
    while True:
        ip = random_ip()
        parts = list(map(int, ip.split('.')))
        if not (parts[0] in (10, 127) or (parts[0] == 172 and 16 <= parts[1] <= 31) or (parts[0] == 192 and parts[1] == 168)):
            return ip


def make_log_line(dt, ip, success=False):
    # Each log line is built to look similar to a real OpenSSH sshd message.
    # The format matters because our parser later searches for exact text such as
    # 'Failed password' and 'from <IP>'.
    port = random.randint(40000, 65000)
    stamp = dt.strftime("%b %d %H:%M:%S")
    if success:
        return f"{stamp} server sshd[1234]: Accepted password for admin from {ip} port {port} ssh2\n"
    return f"{stamp} server sshd[1234]: Failed password for invalid user root from {ip} port {port} ssh2\n"


# We create a unique file name to avoid overwriting previous log samples.
# Example: sample_auth.log, sample_auth1.log, sample_auth2.log
base_name = "sample_auth"
file_name = f"{base_name}.log"
counter = 1
while os.path.exists(file_name):
    file_name = f"{base_name}{counter}.log"
    counter += 1

# We want a mix of malicious-looking traffic and background noise.
# suspicious_ip_count controls how many unique attacker IPs will be created.
# The random choice makes each generated file slightly different.
suspicious_ip_count = random.randint(1, 4)
suspicious_ips = [random_non_private_ip() for _ in range(suspicious_ip_count)]
lines = []

for ip in suspicious_ips:
    # A suspicious source gets a burst of failed logins over a short time range.
    # This intentionally simulates a brute-force attack, which is the pattern we want
    # the parser to detect.
    burst_size = random.randint(5, 12)
    start_dt = datetime(2026, 1, 15, 8, random.randint(0, 59), random.randint(0, 59))
    for _ in range(burst_size):
        delta = timedelta(seconds=random.randint(5, 75))
        start_dt += delta
        lines.append(make_log_line(start_dt, ip, success=False))

# Background traffic adds realistic noise and helps create a more believable log.
# This is important because a detection system must distinguish between suspicious
# attacks and ordinary user activity.
noise_count = random.randint(20, 50)
for _ in range(noise_count):
    ip = random_non_private_ip()
    dt = datetime(2026, 1, 15, 8, random.randint(0, 59), random.randint(0, 59))
    success = random.random() < 0.7
    lines.append(make_log_line(dt, ip, success=success))

# shuffle makes the file look more natural, because real logs are not always grouped by event type.
random.shuffle(lines)

# Open the output file, write all log lines, and close it immediately.
# The with statement is a safe pattern because it ensures the file is closed correctly.
with open(file_name, "w", encoding="utf-8") as f:
    for line in lines:
        f.write(line)

# The user sees a simple success message with the generated file name and the count.
# This is useful for validation and for demonstrating that the script produced data.
print(f"Success! Created {file_name} with {len(lines)} lines of realistic traffic. Suspicious IPs: {suspicious_ip_count}.")
print()
