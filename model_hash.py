import hashlib

def compute_file_hash(filepath):
    sha256_hash = hashlib.sha256()
    with open(filepath, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

model_hash = compute_file_hash('vader_sentiment_model.pkl')

# Print the hash
print(f"Model Hash: {model_hash}")

# Save the hash to a file
with open("model_hash.txt", "w") as hash_file:
    hash_file.write(model_hash)
