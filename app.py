import streamlit as st
import pandas as pd
from log_parser import parse_log
from utils import detect_suspicious_activity
from anomaly_detector import detect_anomalies
# Simple Authentication Layer
def check_login(username, password):
    return username == "admin" and password == "secure123"

if "authenticated" not in st.session_state:
    st.session_state.authenticated = False

if not st.session_state.authenticated:
    st.title("SOC Dashboard Login")

    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Login"):
        if check_login(username, password):
            st.session_state.authenticated = True
            st.rerun()
        else:
            st.error("Invalid credentials")

    st.stop()

st.set_page_config(page_title="AI Threat Log Analyzer", layout="wide")

st.title("AI-Powered Threat Log Analyzer")
st.markdown("Hybrid Threat Detection System Using Rule-Based Analysis and Machine Learning")

uploaded_file = st.file_uploader("Upload Log File", type=["log", "txt"])

if uploaded_file is not None:

    # Parse logs
    df = parse_log(uploaded_file)

    # Apply rule-based detection
    analyzed_df = detect_suspicious_activity(df)

    # Apply anomaly detection
    anomaly_results = detect_anomalies(df)

    suspicious_df = analyzed_df[analyzed_df["Suspicious"] == True]
    anomalous_ips = anomaly_results[anomaly_results["Anomaly"] == True]
    # Escalation Logic: Correlate anomaly with severity
    anomalous_ip_list = anomalous_ips.index.tolist()

    def escalate_severity(row):
        if row["IP"] in anomalous_ip_list and row["Severity"] in ["High", "Medium"]:
            return "Critical"
        return row["Severity"]

    suspicious_df["Severity"] = suspicious_df.apply(escalate_severity, axis=1)

    risk_score = (len(suspicious_df) / len(df)) * 100

    # Sidebar Metrics
    st.sidebar.header("Security Overview")
    st.sidebar.metric("Total Logs Processed", len(df))
    st.sidebar.metric("Suspicious Events Detected", len(suspicious_df))
    st.sidebar.metric("Anomalous IP Addresses", len(anomalous_ips))
    st.sidebar.metric("Overall Risk Score (%)", round(risk_score, 2))

    # Filtering
    st.markdown("### Filter Suspicious Logs")
    selected_ip = st.selectbox(
        "Filter by IP Address",
        ["All"] + sorted(df["IP"].unique().tolist())
    )

    if selected_ip != "All":
        suspicious_df = suspicious_df[suspicious_df["IP"] == selected_ip]

    # Suspicious Logs Section
    st.markdown("### Suspicious Log Entries")
    display_df = suspicious_df.sort_values(
        by=["Severity"],
        ascending=False
    ).reset_index(drop=True)

    display_df.index = display_df.index + 1  # Start numbering from 1

    st.dataframe(display_df)

    st.download_button(
        label="Export Suspicious Logs",
        data=suspicious_df.to_csv(index=False),
        file_name="suspicious_logs.csv",
        mime="text/csv"
    )

    # Anomaly Detection Results
    st.markdown("---")
    st.markdown("### Anomaly Detection Results (IP-Level)")
    st.dataframe(anomaly_results)

    # IP Risk Analysis Table
    st.markdown("---")
    st.markdown("### IP Risk Analysis")

    ip_summary = analyzed_df.groupby("IP").agg(
        Total_Requests=("Status", "count"),
        Failed_Logins=("Status", lambda x: (x == 401).sum()),
        Forbidden_Attempts=("Status", lambda x: (x == 403).sum()),
        Server_Errors=("Status", lambda x: (x == 500).sum())
    )

    ip_summary["Suspicious_Flag"] = ip_summary.index.isin(suspicious_df["IP"])

    ip_summary = ip_summary.sort_values(
        by=["Failed_Logins", "Forbidden_Attempts"],
        ascending=False
    )

    st.dataframe(ip_summary)
    