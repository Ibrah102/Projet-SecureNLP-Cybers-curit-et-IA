import joblib
from nltk.sentiment.vader import SentimentIntensityAnalyzer
from cryptography.fernet import Fernet

analyzer = SentimentIntensityAnalyzer()
key = Fernet.generate_key()
cipher = Fernet(key)

joblib.dump(analyzer, 'vader_sentiment_model.pkl')
joblib.dump(key, 'encryption_key.pkl')

print("VADER model and encryption key have been saved successfully.")