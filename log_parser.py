from collections import Counter

failed_attempts = Counter()

print("--- Starting Security Log Analysis ---")

# Open and read the server log file
with open("server_logs.txt", "r") as file:
    for line in file:
        if "Failed password attempt" in line:
            parts = line.split("IP: ")
            if len(parts) > 1:
                ip_address = parts[1].strip()
                failed_attempts[ip_address] += 1

# Open a new text file to write out the security report automatically
with open("security_alerts.txt", "w") as report_file:
    report_file.write("=== LOG ANALYSIS SECURITY REPORT ===\n")
   
    for ip, count in failed_attempts.items():
        if count >= 3:
            alert_msg = f"[ALERT] Security Incident: IP {ip} flagged for brute-force patterns ({count} failed logins).\n"
            print(alert_msg.strip())  # Prints to your screen
            report_file.write(alert_msg)  # Saves directly to the file
           
print("--- Analysis Complete. Report saved to security_alerts.txt ---")
