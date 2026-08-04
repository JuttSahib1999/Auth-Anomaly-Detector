# Release Notes - v1.0.0

**Release Date:** Initial Release

This is the official Version 1 release of the **Auth Anomaly Detector**. This project is designated as complete and stable; no future updates are planned by the author.

### Features Included in v1.0.0:
*   Implemented log parsing engine supporting standard CSV login formats.
*   Integrated Scikit-Learn `IsolationForest` model for unsupervised anomaly detection.
*   Engineered feature extraction designed specifically for brute-force and password-spraying identification.
*   Added `generate_sample_logs.py` to allow users to instantly simulate malicious and benign traffic for testing.
*   Command-line interface (CLI) support for integration into broader SOC workflows.