"""
Auth Anomaly Detector - Log Generator
Author: Abdul Muqeet Tabraiz
LinkedIn: https://www.linkedin.com/in/abdul-muqeet-tabraiz/
GitHub: https://github.com/JuttSahib1999
Version: 1.0.0

Description: Generates a synthetic CSV dataset containing normal user logins, 
a simulated brute-force attack, and a simulated password spraying attack.
"""

import pandas as pd
import random
from datetime import datetime, timedelta

def generate_logs():
    data = []
    base_time = datetime.now() - timedelta(days=1)
    
    # 1. Generate Normal Traffic (Benign)
    # Regular users logging in successfully, occasionally failing a password once or twice.
    normal_ips = [f"192.168.1.{i}" for i in range(10, 50)]
    for ip in normal_ips:
        username = f"user_{ip.split('.')[-1]}"
        attempts = random.randint(1, 4)
        for _ in range(attempts):
            status = random.choices(["success", "failed"], weights=[0.8, 0.2])[0]
            log_time = base_time + timedelta(minutes=random.randint(1, 1440))
            data.append([log_time.strftime("%Y-%m-%d %H:%M:%S"), ip, username, status])

    # 2. Generate Brute Force Attack (Anomaly)
    # One IP attempting to log into a single account hundreds of times.
    brute_ip = "10.0.0.99"
    brute_target = "admin"
    for _ in range(150):
        log_time = base_time + timedelta(seconds=random.randint(1, 3600))
        data.append([log_time.strftime("%Y-%m-%d %H:%M:%S"), brute_ip, brute_target, "failed"])

    # 3. Generate Password Spraying Attack (Anomaly)
    # One IP trying a few common passwords across many different accounts.
    spray_ip = "172.16.0.45"
    for i in range(1, 80):
        spray_target = f"user_{i}"
        log_time = base_time + timedelta(seconds=random.randint(1, 7200))
        data.append([log_time.strftime("%Y-%m-%d %H:%M:%S"), spray_ip, spray_target, "failed"])

    # Shuffle and create DataFrame
    random.shuffle(data)
    df = pd.DataFrame(data, columns=["timestamp", "ip_address", "username", "status"])
    
    # Sort chronologically to make it look like a real log
    df = df.sort_values(by="timestamp").reset_index(drop=True)
    
    output_file = "auth_logs.csv"
    df.to_csv(output_file, index=False)
    print(f"[+] Successfully generated synthetic dataset: {output_file}")
    print("    Contains: Normal traffic, Brute-force simulation, and Password Spraying simulation.")

if __name__ == "__main__":
    generate_logs()