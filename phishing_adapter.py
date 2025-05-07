import sys
import numpy as np
import pickle
import pandas as pd
sys.path.append('/Users/alexleslie/ml-router-project/Capstone.ipynb')
from Phishing import best_model #Import the trained model

# Load the trained model and scaler
with open('/Users/alexleslie/ml-router-project/phishing_model.pkl', 'rb') as model_file:
    best_model = pickle.load(model_file)

with open('/Users/alexleslie/ml-router-project/scaler.pkl', 'rb') as scaler_file:
    scaler = pickle.load(scaler_file)

# Load the feature names
with open('/Users/alexleslie/ml-router-project/features.pkl', 'rb') as features_file:
    feature_names = pickle.load(features_file)

# Define the feature extraction function
def extract_features(url):
    """Extract all 35 features required by the model."""
    # Length-based features
    length_url = len(url)
    length_hostname = len(url.split('/')[2]) if '//' in url else len(url)

    # Boolean indicator for IP address
    ip = int(any(char.isdigit() for char in url.split('/')[2]) if '//' in url else 0)  # Move `ip` here

    # Character counts
    nb_dots = url.count(".")
    nb_hyphens = url.count("-")
    nb_at = url.count("@")
    nb_qm = url.count("?")
    nb_and = url.count("&")
    nb_or = url.count("|")
    nb_eq = url.count("=")
    nb_underscore = url.count("_")
    nb_tilde = url.count("~")
    nb_percent = url.count("%")
    nb_slash = url.count("/")
    nb_star = url.count("*")
    nb_colon = url.count(":")
    nb_comma = url.count(",")
    nb_semicolumn = url.count(";")
    nb_dollar = url.count("$")
    nb_space = url.count(" ")

    # Boolean indicators
    nb_www = url.count("www")
    nb_com = url.count(".com")
    nb_dslash = url.count("//")
    http_in_path = int("http" in url.split('/')[3:]) if len(url.split('/')) > 3 else 0
    https_token = int("https" in url)

    # Ratios
    ratio_digits_url = sum(c.isdigit() for c in url) / len(url)
    ratio_digits_host = sum(c.isdigit() for c in url.split('/')[2]) / len(url.split('/')[2]) if '//' in url else 0

    # Other features
    punycode = int("xn--" in url)
    shortening_service = int(any(short in url for short in ["bit.ly", "goo.gl", "tinyurl"]))
    path_extension = int("." in url.split('/')[-1])
    phish_hints = int(any(hint in url for hint in ["login", "secure", "account", "update"]))
    domain_in_brand = 0  # Placeholder (requires domain knowledge)
    brand_in_subdomain = 0  # Placeholder (requires domain knowledge)
    brand_in_path = 0  # Placeholder (requires domain knowledge)
    suspecious_tld = int(any(tld in url for tld in [".zip", ".xyz", ".tk", ".top"]))

    # Combine all features into a single list
    return [
        length_url, length_hostname, ip, nb_dots, nb_hyphens, nb_at, nb_qm, nb_and, nb_or, nb_eq,
        nb_underscore, nb_tilde, nb_percent, nb_slash, nb_star, nb_colon, nb_comma, nb_semicolumn,
        nb_dollar, nb_space, nb_www, nb_com, nb_dslash, http_in_path, https_token, ratio_digits_url,
        ratio_digits_host, punycode, shortening_service, path_extension, phish_hints, domain_in_brand,
        brand_in_subdomain, brand_in_path, suspecious_tld
    ]

# Define the predict function
def predict(input_data):
    # Extract the URL from input_data
    url = input_data.get("url")

    # Extract features from the URL
    features = extract_features(url)

    # Convert the features into a DataFrame with column names
    features_df = pd.DataFrame([features], columns=feature_names)

    # Scale the features using the saved scaler
    scaled_features = scaler.transform(features_df)  # Ensure it's a 2D array

    # Use the model for prediction
    prediction = best_model.predict(scaled_features)
    return prediction
