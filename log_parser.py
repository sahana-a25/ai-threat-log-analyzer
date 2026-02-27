import re
import pandas as pd

def parse_log(file):
    log_pattern = r'(\d+\.\d+\.\d+\.\d+) - - \[(.*?)\] "(.*?) (.*?)" (\d+)'
    
    logs = []
    
    for line in file:
        line = line.decode("utf-8")
        match = re.match(log_pattern, line)
        
        if match:
            ip = match.group(1)
            timestamp = match.group(2)
            method = match.group(3)
            url = match.group(4)
            status = int(match.group(5))
            
            logs.append([ip, timestamp, method, url, status])
    
    df = pd.DataFrame(logs, columns=["IP", "Timestamp", "Method", "URL", "Status"])

    # Convert Timestamp to datetime
    df["Timestamp"] = pd.to_datetime(
        df["Timestamp"],
        format="%d/%b/%Y:%H:%M:%S",
        errors="coerce"
    )

    return df