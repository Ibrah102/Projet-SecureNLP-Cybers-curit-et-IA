import streamlit as st
import joblib
from nltk.sentiment.vader import SentimentIntensityAnalyzer
from cryptography.fernet import Fernet
import datetime
import hashlib
import bcrypt

# Load the saved VADER model and encryption key
analyzer = joblib.load('vader_sentiment_model.pkl')
key = joblib.load('encryption_key.pkl')
cipher = Fernet(key)

# ========================
# Log Function
# ========================
def log_action(action):
    with open("log_access.txt", "a") as log_file:
        log_file.write(f"[{datetime.datetime.now()}] {action}\n")

# ========================
# Auth Section with hashed passwords
# ========================
USER_CREDENTIALS = {
    "data_scientist": bcrypt.hashpw("ds_pass_123".encode(), bcrypt.gensalt()).decode(),
    "analyst": bcrypt.hashpw("analyst_pass_456".encode(), bcrypt.gensalt()).decode()
}

# ========================
# Check Model Integrity
# ========================
def compute_file_hash(filepath):
    sha256_hash = hashlib.sha256()
    with open(filepath, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def check_model_integrity(model_path):
    expected_hash = "1d33178269f7340f041f7475b609329470923ab84b798871e792216a2672a643"  # You can store the hash you calculated earlier
    file_hash = compute_file_hash(model_path)
    return file_hash == expected_hash

# ========================
# Streamlit Interface
# ========================
st.title("🔐 SecureNLP Sentiment Analysis")

role = st.selectbox("Choose your role", ["data_scientist", "analyst"])
password = st.text_input("Enter password", type="password")

# Initialize session state if not already present
if 'decrypted_sentiment' not in st.session_state:
    st.session_state.decrypted_sentiment = None

if 'encrypted_sentiment' not in st.session_state:
    st.session_state.encrypted_sentiment = None

# Validate password
if bcrypt.checkpw(password.encode('utf-8'), USER_CREDENTIALS.get(role).encode('utf-8')):
    st.success(f"Authenticated as {role}")
    log_action(f"{role} logged in")

    # Check model integrity
    if check_model_integrity('vader_sentiment_model.pkl'):
        st.success("Model integrity verified.")
    else:
        st.error("Model integrity check failed!")

    text = st.text_area("💬 Enter a comment to analyze:")

    if st.button("🔍 Analyze Sentiment"):
        if text.strip():
            # Analyze sentiment using VADER
            sentiment_score = analyzer.polarity_scores(text)
            sentiment = "POSITIVE" if sentiment_score['compound'] >= 0 else "NEGATIVE"
            encrypted_sentiment = cipher.encrypt(sentiment.encode()).decode()

            # Store the encrypted sentiment in session state
            st.session_state.encrypted_sentiment = encrypted_sentiment
            st.session_state.decrypted_sentiment = None  # Reset decrypted sentiment when new prediction is made

            # Show encrypted prediction
            st.write("✅ Encrypted Prediction:")
            st.code(encrypted_sentiment)
            log_action(f"{role} made a prediction")

    if role == "data_scientist" and st.session_state.encrypted_sentiment:
        # Decrypt the sentiment and display it only for the data scientist role
        if st.button("🔓 Decrypt Prediction"):
            # Ensure decryption is only done once
            if st.session_state.decrypted_sentiment is None:
                st.session_state.decrypted_sentiment = cipher.decrypt(st.session_state.encrypted_sentiment.encode()).decode()
                st.success(f"🔍 Decrypted Sentiment: {st.session_state.decrypted_sentiment}")
                log_action(f"{role} decrypted a prediction")
            else:
                st.warning("Prediction already decrypted.")
else:
    st.warning("Incorrect password. Please try again.")

# Show decrypted sentiment if available
if st.session_state.get('decrypted_sentiment'):
    st.write(f"🔓 Decrypted Prediction: {st.session_state.decrypted_sentiment}")
