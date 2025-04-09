import streamlit as st
import joblib
import nltk
from nltk.sentiment.vader import SentimentIntensityAnalyzer
from cryptography.fernet import Fernet
import datetime
import hashlib
import bcrypt
import os

# Download NLTK data (required for VADER)
nltk.download('vader_lexicon')

# Load model and key with absolute paths
model_path = os.path.join(os.path.dirname(__file__), 'vader_sentiment_model.pkl')
key_path = os.path.join(os.path.dirname(__file__), 'encryption_key.pkl')

try:
    analyzer = joblib.load(model_path)
    key = joblib.load(key_path)
    cipher = Fernet(key)
except Exception as e:
    st.error(f"Error loading model or key: {str(e)}")
    st.stop()

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
    expected_hash = "1d33178269f7340f041f7475b609329470923ab84b798871e792216a2672a643"
    file_hash = compute_file_hash(model_path)
    return file_hash == expected_hash

# ========================
# Streamlit Interface
# ========================
st.title("🔐 SecureNLP Sentiment Analysis")
st.markdown(
    """
    <div style="position: fixed; bottom: 10px; left: 10px; color: #888; font-size: 0.8em;">
        FOUITEH Ibrahim<br>
        GHARBAOUI Hala
    </div>
    """,
    unsafe_allow_html=True
)
st.markdown("data_scientist: ds_pass_123 /n analyst: analyst_pass_456")
# Clear session state when switching roles
if 'previous_role' not in st.session_state:
    st.session_state.previous_role = None

role = st.selectbox("Choose your role", ["data_scientist", "analyst"])

# Reset predictions when role changes
if role != st.session_state.previous_role:
    st.session_state.encrypted_sentiment = None
    st.session_state.decrypted_sentiment = None
    st.session_state.previous_role = role

password = st.text_input("Enter password", type="password")

# Initialize session state
if 'decrypted_sentiment' not in st.session_state:
    st.session_state.decrypted_sentiment = None
if 'encrypted_sentiment' not in st.session_state:
    st.session_state.encrypted_sentiment = None

# Validate password
if role in USER_CREDENTIALS and bcrypt.checkpw(password.encode('utf-8'), USER_CREDENTIALS[role].encode('utf-8')):
    st.success(f"Authenticated as {role}")
    log_action(f"{role} logged in")

    # Check model integrity
    if check_model_integrity(model_path):
        st.success("Model integrity verified.")
    else:
        st.error("Model integrity check failed!")

    text = st.text_area("💬 Enter a comment to analyze:")

    if st.button("🔍 Analyze Sentiment") and text.strip():
        sentiment_score = analyzer.polarity_scores(text)
        sentiment = "POSITIVE" if sentiment_score['compound'] >= 0 else "NEGATIVE"
        encrypted_sentiment = cipher.encrypt(sentiment.encode()).decode()

        st.session_state.encrypted_sentiment = encrypted_sentiment
        st.session_state.decrypted_sentiment = None

        st.write("✅ Encrypted Prediction:")
        st.code(encrypted_sentiment)
        log_action(f"{role} made a prediction")

    if role == "data_scientist" and st.session_state.encrypted_sentiment:
        if st.button("🔓 Decrypt Prediction"):
            if st.session_state.decrypted_sentiment is None:
                st.session_state.decrypted_sentiment = cipher.decrypt(
                    st.session_state.encrypted_sentiment.encode()
                ).decode()
                log_action(f"{role} decrypted a prediction")
            else:
                st.warning("Prediction already decrypted.")
            
            # Only show the green success message, not the duplicate
            st.success(f"🔍 Decrypted Sentiment: {st.session_state.decrypted_sentiment}")
else:
    st.warning("Incorrect password. Please try again.")
