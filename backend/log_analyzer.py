import re
from collections import Counter

def analyze_log(file_content):
    suspicious = {
        "sql_injection": [],
        "path_traversal": [],
        "failed_logins": []
    }

    ip_counter = Counter()

    lines = file_content.splitlines()

    for line in lines:
        # Extract IP address
        ip_match = re.match(r"(\d+\.\d+\.\d+\.\d+)", line)
        if ip_match:
            ip = ip_match.group(1)
            ip_counter[ip] += 1

        # SQL Injection detection
        if re.search(r"(\%27)|(\')|(\-\-)|(\%23)|(#)", line):
            suspicious["sql_injection"].append(line)

        # Path Traversal detection
        if "../" in line or "..\\" in line:
            suspicious["path_traversal"].append(line)

        # Failed login detection
        if "failed" in line.lower() or "unauthorized" in line.lower():
            suspicious["failed_logins"].append(line)

    suspicious_ips = {
        ip: count for ip, count in ip_counter.items() if count > 5
    }

    return {
        "suspicious_ips": suspicious_ips,
        "sql_injection_attempts": len(suspicious["sql_injection"]),
        "path_traversal_attempts": len(suspicious["path_traversal"]),
        "failed_login_attempts": len(suspicious["failed_logins"])
    }
