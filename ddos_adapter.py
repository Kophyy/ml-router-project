import numpy as np
import sys

# Add the path to your trained DDoS model
sys.path.append('/Users/alexleslie/ml-router-project/DoS-Detection')
from dos_rf_hp import best_model  # Import your RandomForest model

def predict(input_data):
    # Extract demo features from input_data (this is where your traffic data will come in)
    packet_rate, unique_ips, avg_packet_size = input_data.get("features", [0, 0, 0])

    # Simple threshold-based logic for demo (simulating a DDoS detection)
    if packet_rate > 1000 and unique_ips > 100 and avg_packet_size > 800:
        return "DoS"  # Simulate a DDoS detection
    else:
        return "Normal"  # Simulate normal traffic (no DDoS)
