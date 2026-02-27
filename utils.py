import pandas as pd

def detect_suspicious_activity(df):

    suspicious_logs = df.copy()

    # Rule Flags
    suspicious_logs["Failed_Login"] = suspicious_logs["Status"] == 401
    suspicious_logs["Forbidden"] = suspicious_logs["Status"] == 403
    suspicious_logs["Server_Error"] = suspicious_logs["Status"] == 500
    suspicious_logs["Sensitive_URL"] = suspicious_logs["URL"].str.contains("admin", case=False)

    # Count failed attempts per IP
    failed_counts = suspicious_logs.groupby("IP")["Failed_Login"].sum()
    suspicious_logs["High_Failed_Attempts"] = suspicious_logs["IP"].map(
        failed_counts > 3
    )

    # Suspicious Flag
    suspicious_logs["Suspicious"] = (
        suspicious_logs["Failed_Login"] |
        suspicious_logs["Forbidden"] |
        suspicious_logs["Server_Error"] |
        suspicious_logs["Sensitive_URL"] |
        suspicious_logs["High_Failed_Attempts"]
    )
    # Time-Based Burst Detection (Brute Force)
    suspicious_logs["Brute_Force"] = False

    for ip in suspicious_logs["IP"].unique():
        ip_logs = suspicious_logs[
            (suspicious_logs["IP"] == ip) &
            (suspicious_logs["Failed_Login"])
        ].sort_values("Timestamp")

        if len(ip_logs) >= 5:
            time_diff = (ip_logs["Timestamp"].max() - ip_logs["Timestamp"].min()).total_seconds()

            if time_diff <= 60:
                suspicious_logs.loc[
                    suspicious_logs["IP"] == ip,
                    "Brute_Force"
                ] = True
    # Severity Scoring Logic
    def assign_severity(row):
        score = 0

        if row["Failed_Login"]:
            score += 1
        if row["Forbidden"]:
            score += 2
        if row["Server_Error"]:
            score += 1
        if row["Sensitive_URL"]:
            score += 3
        if row["High_Failed_Attempts"]:
            score += 2
        if row["Brute_Force"]:
            score += 4

        if score >= 6:
            return "Critical"
        elif score >= 4:
            return "High"
        elif score >= 2:
            return "Medium"
        elif score >= 1:
            return "Low"
        else:
            return "None"

    suspicious_logs["Severity"] = suspicious_logs.apply(assign_severity, axis=1)

    return suspicious_logs