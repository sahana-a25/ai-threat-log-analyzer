import pandas as pd

def detect_suspicious_activity(df):
    
    suspicious_logs = df.copy()
    
    # Rule 1: Failed login attempts (status 401)
    suspicious_logs["Failed_Login"] = suspicious_logs["Status"] == 401
    
    # Rule 2: Forbidden access (403)
    suspicious_logs["Forbidden"] = suspicious_logs["Status"] == 403
    
    # Rule 3: Server error (500)
    suspicious_logs["Server_Error"] = suspicious_logs["Status"] == 500
    
    # Rule 4: Accessing sensitive URLs
    suspicious_logs["Sensitive_URL"] = suspicious_logs["URL"].str.contains("admin", case=False)
    
    # Count failed attempts per IP
    failed_counts = suspicious_logs.groupby("IP")["Failed_Login"].sum()
    
    suspicious_logs["High_Failed_Attempts"] = suspicious_logs["IP"].map(
        failed_counts > 2
    )
    
    # Final suspicious flag
    suspicious_logs["Suspicious"] = (
        suspicious_logs["Failed_Login"] |
        suspicious_logs["Forbidden"] |
        suspicious_logs["Server_Error"] |
        suspicious_logs["Sensitive_URL"] |
        suspicious_logs["High_Failed_Attempts"]
    )
    
    return suspicious_logs