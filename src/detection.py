# src/detection.py
from sklearn.ensemble import IsolationForest
import numpy as np
from src.traffic import packets

packet_counts = []

def analyze_traffic():
    global packet_counts
    if len(packets) > 0:
        packet_counts.append(1)  # Increment for each packet
    if len(packet_counts) < 10:
        return "Collecting data..."
    model = IsolationForest(contamination=0.1, random_state=42)
    data = np.array(packet_counts).reshape(-1, 1)
    predictions = model.fit_predict(data)
    return "ALERT: Threat detected!" if -1 in predictions[-5:] else "Traffic normal"