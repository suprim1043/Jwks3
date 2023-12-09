#ss2139
#Suprim Sedhai
import os
import time
import uuid
import jwt
import sqlite3
from datetime import datetime, timedelta
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from flask import Flask, request, jsonify

app = Flask(__name__)

# Defining Constants
PRIVATE_KEY_FILE = "private_key.pem"
PUBLIC_KEY_FILE = "public_key.pem"
KEY_EXPIRY_DAYS = 30
SECRET_KEY = "your-secret-key"
DATABASE_FILE = "database.db"

# Check if keys exist, otherwise generate them
if not os.path.exists(PRIVATE_KEY_FILE) or not os.path.exists(PUBLIC_KEY_FILE):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    with open(PRIVATE_KEY_FILE, "wb") as private_key_file:
        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
        private_key_file.write(private_key_pem)

    public_key = private_key.public_key()

    with open(PUBLIC_KEY_FILE, "wb") as public_key_file:
        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        public_key_file.write(public_key_pem)

# Load private and public keys
with open(PRIVATE_KEY_FILE, "rb") as key_file:
    private_key = serialization.load_pem_private_key(
        key_file.read(),
        password=None,
        backend=default_backend()
    )

with open(PUBLIC_KEY_FILE, "rb") as public_key_file:
    public_key_data = public_key_file.read()
    public_key = serialization.load_pem_public_key(public_key_data, backend=default_backend())

# Load AES key from environment variable
AES_KEY = os.getenv("NOT_MY_KEY").encode()

# Initialize database
conn = sqlite3.connect(DATABASE_FILE)
cursor = conn.cursor()

# Create users table if not exists
cursor.execute('''
    CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        email TEXT UNIQUE,
        date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_login TIMESTAMP
    )
''')

# Create auth_logs table if not exists
cursor.execute('''
    CREATE TABLE IF NOT EXISTS auth_logs(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        request_ip TEXT NOT NULL,
        request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        user_id INTEGER,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )
''')

# Commit changes and close the connection
conn.commit()
conn.close()

# Helper function for AES encryption
def encrypt_private_key(private_key, key):
    cipher = Cipher(algorithms.AES(key), modes.CFB8(iv=b'12345678'))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )) + encryptor.finalize()
    return ciphertext

# Helper function for AES decryption
def decrypt_private_key(ciphertext, key):
    cipher = Cipher(algorithms.AES(key), modes.CFB8(iv=b'12345678'))
    decryptor = cipher.decryptor()
    private_key_pem = decryptor.update(ciphertext) + decryptor.finalize()
    private_key = serialization.load_pem_private_key(private_key_pem, password=None, backend=default_backend())
    return private_key

# JWKS entry creation
kid = "my-key-id"
expiry = datetime.utcnow() + timedelta(days=KEY_EXPIRY_DAYS)
jwks_entry = {
    "kid": kid,
    "kty": "RSA",
    "alg": "RS256",
    "use": "sig",
    "n": public_key.public_numbers().n,
    "e": public_key.public_numbers().e,
    "exp": int(expiry.timestamp())
}


users = {}

# Register endpoint for user registration
@app.route("/register", methods=["POST"])
def register():
    global private_key, users

    # Accept user registration details
    data = request.get_json()
    username = data.get("username")
    email = data.get("email")

    
    password = str(uuid.uuid4())


    password_hash = hash_password(password)

    # Store user details
    user_id = store_user(username, password_hash, email)
    return jsonify({"password": password}), 201


# Auth endpoint for authentication
@app.route("/auth", methods=["POST"])
def authenticate():
    global private_key, users

    # Obtain user_id during authentication 
    username = request.json.get("username")
    user_id = users.get(username, {}).get("id")
    log_auth_request(request.remote_addr, user_id)
    valid_credentials = authenticate_user(username, request.json.get("password"))

    if valid_credentials:
        # Generate a JWT with the current key
        payload = {"sub": username, "exp": int((datetime.utcnow() + timedelta(days=1)).timestamp())}
        token = jwt.encode(payload, private_key, algorithm="RS256", headers={"kid": kid})
        return jsonify({"token": token})
    else:
        return jsonify({"error": "Unauthorized"}), 401

# Updated log_auth_request function
def log_auth_request(request_ip, user_id):
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO auth_logs (request_ip, user_id)
        VALUES (?, ?)
    ''', (request_ip, user_id))
    conn.commit()
    conn.close()
    

def authenticate_user(username, password):
    global users
    user = users.get(username)
    print(f"Username: {username}, Password: {password}, User: {user}")

    if user and verify_password(user.get("password_hash"), password.encode()):
        print("Authentication successful")
        return True
    else:
        print("Authentication failed")
        return False





# Auth Logs endpoint to retrieve authentication logs

@app.route("/auth_logs", methods=["GET"])
def get_auth_logs():
    # Retrieve authentication logs from the database
    logs = retrieve_auth_logs()
    return jsonify({"auth_logs": logs})

# Helper function to retrieve authentication logs from the database
def retrieve_auth_logs():
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    cursor.execute('''
        SELECT * FROM auth_logs
    ''')
    logs = cursor.fetchall()
    conn.close()
    return logs

# Helper function to hash the password using Argon2
def hash_password(password):
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())
    return salt + key



def verify_password(stored_hash, provided_password):
    salt = stored_hash[:16]
    key = stored_hash[16:]
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    derived_key = kdf.derive(provided_password)
    return derived_key == key




def store_user(username, password_hash, email):
    global users

    # Insert user details into the users table
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO users (username, password_hash, email)
        VALUES (?, ?, ?)
    ''', (username, password_hash, email))
    user_id = cursor.lastrowid
    conn.commit()
    conn.close()

    # Update the in-memory users dictionary
    users[username] = {"id": user_id, "password_hash": password_hash, "email": email}

    return user_id

if __name__ == "__main__":
    app.run(port=8080, debug=True)

