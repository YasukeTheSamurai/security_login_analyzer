"""
Security Login Analyzer
Module: analyzer.py

Purpose: Analyze parsed authentication logs to 
identify potential security threats and anomalies.

"""

import parser
from datetime import datetime, timedelta

def count_ip_addresses(logs):
    ip_counts = {}

    for entry in logs:
        ip = entry.get("ip")

        if ip not in ip_counts:
            ip_counts[ip] = 1
        else:
            ip_counts[ip] += 1

    return ip_counts

def count_failed_logins(logs):
    failed_count = 0

    for entry in logs:
        if entry.get("status") == "Failed":
            failed_count += 1

    return failed_count



def count_failed_logins_by_ip(logs):
    
    failed_ip_counts = {}

    for entry in logs:
        if entry.get("status") == "Failed":
            ip = entry.get("ip")

            if ip not in failed_ip_counts:
                failed_ip_counts[ip] = 1
            else:
                failed_ip_counts[ip] += 1
   

    return failed_ip_counts

def count_successful_logins_by_ip(logs):
    successful_ip_counts = {}

    for entry in logs:
        if entry.get("status") == "Accepted":
            ip = entry.get("ip")

            if ip not in successful_ip_counts:
                successful_ip_counts[ip] = 1
            else:
                successful_ip_counts[ip] += 1

    return successful_ip_counts

def detect_brute_force_attempts(logs, threshold=5, window_minutes=5):
    suspicious_ips = {}
    failed_login_times = {}
    window = timedelta(minutes=window_minutes)

    for entry in logs:
        if entry.get("status") == "Failed":
            ip = entry.get("ip")
            timestamp_str = entry.get("timestamp")

            # Convert timestamp string to datetime object
            timestamp = datetime.strptime(f'2026 {timestamp_str}', "%Y %b %d %H:%M:%S")

            if ip not in failed_login_times:
                failed_login_times[ip] = [timestamp]
            else:
                failed_login_times[ip].append(timestamp)

    for ip, timestamps in failed_login_times.items():
        timestamps.sort()  # Sort timestamps for the IP

        for i in range(len(timestamps) - threshold + 1):
            time1 = timestamps[i]
            time2 = timestamps[i + threshold - 1]
            converted_times = []

            for timestamp in timestamps:
                login_time = timestamp
                converted_times.append(timestamp)

            converted_times.sort()  # Sort timestamps for the IP

            difference = time2 - time1

            print(f"IP: {ip}, Difference: {difference}, Window: {window}")
            
            if difference <= window:
                suspicious_ips[ip] = len(timestamps)
                break  # No need to check further for this IP   
 

    return suspicious_ips

    results = detect_brute_force_attempts(logs, threshold=5, window_minutes=5)
    print("Suspicious IPs with potential brute-force attempts: \n", results)


if __name__ == "__main__":
    logs = parser.read_log_file("logs/auth.log")  # Read and parse the log file

    # successful_results = count_successful_logins_by_ip(logs)
    # print("\nSuccessful Login Attempts: \n", successful_results)


    # failed_results = count_failed_logins_by_ip(logs)
    # print("\nFailed Login Attempts:\n", failed_results)

    results = detect_brute_force_attempts(logs, threshold=3, window_minutes=5)
    print("\nSuspicious IPs with potential brute-force attempts: \n", results)

    
