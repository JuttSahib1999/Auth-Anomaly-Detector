# Auth Anomaly Detector

An AI-based authentication anomaly detector that leverages the **Isolation Forest** machine learning algorithm to analyze login logs. The tool is designed to automatically detect brute-force attacks, password spraying, and unusual login behaviors by evaluating the behavioral characteristics of incoming IP addresses.

---

## Features

* **Feature Engineering:** Extracts intelligent metrics from standard raw login logs (total attempts, failure rates, unique accounts targeted).
* **Machine Learning:** Utilizes Scikit-Learn's `IsolationForest` to isolate outlier behavior without requiring a pre-labeled dataset.
* **Threat Detection:** Built to natively surface Brute Force (high failure volume) and Password Spraying (many unique usernames from a single IP) attacks.
* **Production Ready:** Clean, modular, and easy to run from the command line.

---

## Installation

1. Clone this repository:
```bash
git clone https://github.com/JuttSahib1999/Auth-Anomaly-Detector.git
cd Auth-Anomaly-Detector

```


2. Install the required Python packages:
```bash
pip install -r requirements.txt

```



---

## Usage

Run the detector against a CSV file containing login logs. The CSV must have the following columns: `timestamp`, `ip_address`, `username`, and `status` (where status is either `success` or `failed`).

```bash
python auth_anomaly_detector.py --input auth_logs.csv --output flagged_anomalies.csv --contamination 0.05

```

If you do not have logs to test, you can generate a synthetic dataset using the provided helper script:

```bash
python generate_sample_logs.py

```

---

## Version

**v1.0.0** *(Stable Release - No further updates planned)*

---

## Author

* **Name:** Abdul Muqeet Tabraiz
* **LinkedIn:** [Abdul Muqeet Tabraiz](https://www.linkedin.com/in/abdul-muqeet-tabraiz/)
* **GitHub:** [JuttSahib1999](https://github.com/JuttSahib1999)