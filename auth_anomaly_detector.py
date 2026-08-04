"""
Auth Anomaly Detector - Core ML Engine
Author: Abdul Muqeet Tabraiz
LinkedIn: https://www.linkedin.com/in/abdul-muqeet-tabraiz/
GitHub: https://github.com/JuttSahib1999
Version: 1.0.0

Description: ML-based script to detect authentication anomalies using Isolation Forest.
"""

import pandas as pd
import numpy as np
import argparse
import sys
from sklearn.ensemble import IsolationForest

def load_and_preprocess(file_path):
    """Loads the CSV file and ensures correct column headers exist."""
    try:
        df = pd.read_csv(file_path)
    except Exception as e:
        print(f"[-] Error reading {file_path}: {e}")
        sys.exit(1)

    required_columns = {"timestamp", "ip_address", "username", "status"}
    if not required_columns.issubset(df.columns):
        print(f"[-] Missing required columns. Expected: {required_columns}")
        sys.exit(1)

    df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
    df['status'] = df['status'].str.lower()
    return df

def extract_features(df):
    """
    Engineers behavioral features grouped by IP address.
    Features:
    - total_attempts: Total logins attempted by the IP.
    - failed_attempts: Total failed logins.
    - unique_usernames: Number of distinct usernames targeted (detects password spraying).
    - failure_ratio: Ratio of failed attempts to total attempts (detects brute force).
    """
    print("[*] Extracting features from logs...")
    
    # Calculate base metrics per IP
    features = df.groupby('ip_address').agg(
        total_attempts=('status', 'count'),
        unique_usernames=('username', 'nunique'),
        failed_attempts=('status', lambda x: (x == 'failed').sum())
    ).reset_index()

    # Calculate failure ratio
    features['failure_ratio'] = features['failed_attempts'] / features['total_attempts']
    
    return features

def detect_anomalies(features_df, contamination_rate):
    """Trains the Isolation Forest model and identifies anomalies."""
    print(f"[*] Training Isolation Forest model (Contamination: {contamination_rate})...")
    
    # Select numeric features for the ML model
    X = features_df[['total_attempts', 'failed_attempts', 'unique_usernames', 'failure_ratio']]
    
    # Initialize and fit the model
    # random_state ensures reproducible results; n_estimators builds 100 trees
    model = IsolationForest(n_estimators=100, contamination=contamination_rate, random_state=42)
    model.fit(X)
    
    # Predict anomalies (-1 for anomaly, 1 for normal)
    features_df['anomaly_score'] = model.decision_function(X)
    features_df['is_anomaly'] = model.predict(X)
    
    # Map -1 to True (Anomaly) and 1 to False (Normal)
    features_df['is_anomaly'] = features_df['is_anomaly'] == -1
    
    return features_df

def main():
    parser = argparse.ArgumentParser(description="AI-based Authentication Anomaly Detector")
    parser.add_argument("-i", "--input", required=True, help="Path to input CSV log file")
    parser.add_argument("-o", "--output", default="anomalies_detected.csv", help="Path to save output results")
    parser.add_argument("-c", "--contamination", type=float, default=0.05, 
                        help="Estimated proportion of outliers in the data (default: 0.05)")
    
    args = parser.parse_args()

    # 1. Load data
    raw_df = load_and_preprocess(args.input)
    print(f"[+] Loaded {len(raw_df)} log entries.")

    # 2. Extract ML Features
    features_df = extract_features(raw_df)
    
    if len(features_df) < 5:
        print("[!] Warning: Dataset contains very few unique IPs. Anomaly detection may be inaccurate.")

    # 3. ML Detection
    results_df = detect_anomalies(features_df, args.contamination)

    # 4. Filter and display anomalies
    anomalies = results_df[results_df['is_anomaly'] == True].sort_values(by='anomaly_score')
    
    print("\n" + "="*50)
    print(" DETECTION RESULTS ".center(50, "="))
    print("="*50)
    
    if anomalies.empty:
        print("[+] No anomalies detected based on the current contamination threshold.")
    else:
        print(f"[!] Detected {len(anomalies)} anomalous IP addresses:")
        for index, row in anomalies.iterrows():
            reason = []
            if row['unique_usernames'] > 5 and row['failure_ratio'] > 0.8:
                reason.append("Possible Password Spraying")
            if row['failed_attempts'] > 20 and row['unique_usernames'] <= 2:
                reason.append("Possible Brute Force")
            
            flag_reason = " & ".join(reason) if reason else "Unusual Behavior"
            
            print(f"\n  [IP]: {row['ip_address']} ({flag_reason})")
            print(f"      - Total Attempts: {row['total_attempts']}")
            print(f"      - Failed Attempts: {row['failed_attempts']} ({(row['failure_ratio']*100):.1f}% fail rate)")
            print(f"      - Distinct Users Targeted: {row['unique_usernames']}")
            print(f"      - ML Anomaly Score: {row['anomaly_score']:.4f}")

    # 5. Save output
    results_df.to_csv(args.output, index=False)
    print(f"\n[+] Full analysis saved to: {args.output}")

if __name__ == "__main__":
    main()