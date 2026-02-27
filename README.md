AI-Powered Threat Log Analyzer
Overview

AI-Powered Threat Log Analyzer is a hybrid security monitoring system that combines rule-based threat detection with machine learning–based anomaly detection to simulate a Security Operations Center (SOC) triage pipeline.

The system processes server log files, detects suspicious behavior, assigns severity levels, and performs anomaly correlation to escalate high-risk activities.

Core Features:
Log file ingestion and parsing
Rule-based threat detection (401, 403, 500, admin access)
IP-level failed login aggregation
Isolation Forest anomaly detection
Correlation-based severity escalation
Risk score calculation
IP risk analysis table
Suspicious log filtering
CSV export functionality

Detection Pipeline:
Log Upload
Structured Parsing
Rule-Based Flagging
Behavioral Feature Engineering
Isolation Forest Anomaly Detection
Severity Scoring Engine
Correlation-Based Escalation
Risk Aggregation & Reporting

Severity Classification:
Severity is assigned based on weighted rule evaluation:
Low
Medium
High
Critical
Events are escalated if anomalous IP behavior correlates with high-risk rule triggers.

Tech Stack:
Python
Streamlit
Pandas
Scikit-learn
Isolation Forest (Unsupervised ML)

Project Structure:
ai-threat-log-analyzer/
│
├── app.py
├── log_parser.py
├── utils.py
├── anomaly_detector.py
├── sample_logs.log
├── requirements.txt
└── README.md


Future Enhancements:
Time-based burst attack detection
Multi-format log parsing (Apache/Nginx)
Authentication layer
Real-time log streaming
Deployment scaling