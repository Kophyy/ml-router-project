import streamlit as st
from phishing_adapter import predict as predict_phishing
from ddos_adapter import predict as predict_ddos

st.title("Network Traffic Threat Detection")
st.subheader("Manually input network traffic attributes")

# Choose the type of traffic to analyze
traffic_type = st.selectbox("Select traffic type to test:", ["phishing", "ddos"])

input_data = {"type": traffic_type}

if traffic_type == "phishing":
    # For phishing, maybe your model expects a URL string
    input_data["url"] = st.text_input("Enter suspicious URL:")

elif traffic_type == "ddos":
   # For DDoS traffic, simulate the attributes we need
    packet_rate = st.number_input("Packet rate (pps):", min_value=0)
    unique_ips = st.number_input("Unique IPs in timeframe:", min_value=0)
    avg_packet_size = st.number_input("Avg packet size (bytes):", min_value=0)
    input_data["features"] = [packet_rate, unique_ips, avg_packet_size]

# Run prediction
if st.button("Analyze Traffic"):
    if traffic_type == "phishing":
        result = predict_phishing(input_data)
    elif traffic_type == "ddos":
        result = predict_ddos(input_data)
    else:
        result = {"error": "Invalid traffic type."}

# Display the result
    st.write("🧠 Prediction:", result)

    if traffic_type == "phishing":
        if result == 1:
            st.write("⚠️ Phishing attempt detected!")
        else:
            st.write("✅ URL is safe.")

    elif traffic_type == "ddos":
        if result == "DoS":
            st.write("🚨 Potential DDoS attack detected.")
        else:
            st.write("✅ Network traffic appears normal.")

