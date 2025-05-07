from phishing_adapter import predict as predict_phishing
from ddos_adapter import predict as predict_ddos

def route_input(input_data):
    input_type = input_data.get("type")

    if input_type == "phishing":
        return predict_phishing(input_data)
    elif input_type == "ddos":
        return predict_ddos(input_data)
    else:
        return {"error": "Unknown input type"}

# Test the router with a sample phishing input
if __name__ == "__main__":
    sample_input = {
        "type": "phishing",
        "url": "http://suspicious.example.com"
    }

    result = route_input(sample_input)
    print("Prediction:", result)