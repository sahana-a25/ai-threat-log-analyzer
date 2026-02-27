import pandas as pd
from sklearn.ensemble import IsolationForest

def detect_anomalies(df):

    # Feature Engineering per IP
    ip_features = df.groupby("IP").agg(
        Request_Count=("Status", "count"),
        Failed_Logins=("Status", lambda x: (x == 401).sum()),
        Forbidden_Attempts=("Status", lambda x: (x == 403).sum()),
        Server_Errors=("Status", lambda x: (x == 500).sum()),
        Unique_URLs=("URL", "nunique")
    )

    # Create Isolation Forest model
    model = IsolationForest(contamination=0.2, random_state=42)

    ip_features["Anomaly"] = model.fit_predict(ip_features)

    # Convert -1 to True (anomaly)
    ip_features["Anomaly"] = ip_features["Anomaly"].apply(lambda x: True if x == -1 else False)

    return ip_features