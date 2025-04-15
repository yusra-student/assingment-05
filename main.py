import streamlit as st
import hashlib
import json
import time
import os
from cryptography.fernet import Fernet
from base64 import urlsafe_b64encode
from hashlib import pbkdf2_hmac

# ===== Constants & Globals =====
DATA_FILE = "secure_data.json"
KEY = Fernet.generate_key()
cipher = Fernet(KEY)

# Load data from file
def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as file:
            return json.load(file)
    return {}

# Save data to file
def save_data(data):
    with open(DATA_FILE, "w") as file:
        json.dump(data, file)

# Initialize session state
if "data" not in st.session_state:
    st.session_state.data = load_data()

if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0

if "lockout_time" not in st.session_state:
    st.session_state.lockout_time = 0

if "authenticated" not in st.session_state:
    st.session_state.authenticated = False

# ===== Helper Functions =====

def pbkdf2_hash(passkey, salt="somesalt"):
    hashed = pbkdf2_hmac('sha256', passkey.encode(), salt.encode(), 100000)
    return urlsafe_b64encode(hashed).decode()

def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(encrypted_text):
    return cipher.decrypt(encrypted_text.encode()).decode()

def store_user_data(username, text, passkey):
    encrypted_text = encrypt_data(text)
    hashed_passkey = pbkdf2_hash(passkey)

    user_data = st.session_state.data.get(username, [])
    user_data.append({
        "encrypted_text": encrypted_text,
        "passkey": hashed_passkey
    })
    st.session_state.data[username] = user_data
    save_data(st.session_state.data)

def retrieve_user_data(username, encrypted_text, passkey):
    hashed_input = pbkdf2_hash(passkey)
    user_entries = st.session_state.data.get(username, [])

    for entry in user_entries:
        if entry["encrypted_text"] == encrypted_text and entry["passkey"] == hashed_input:
            st.session_state.failed_attempts = 0
            return decrypt_data(encrypted_text)
    
    st.session_state.failed_attempts += 1
    if st.session_state.failed_attempts >= 3:
        st.session_state.lockout_time = time.time()
    return None

# ===== Streamlit UI =====
st.title("🔐 Secure Data Encryption System")

menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.selectbox("Navigation", menu)

# ===== Lockout Check =====
if st.session_state.failed_attempts >= 3:
    lock_duration = 30  # seconds
    elapsed = time.time() - st.session_state.lockout_time
    if elapsed < lock_duration and not st.session_state.authenticated:
        st.warning(f"⏳ Too many failed attempts. Please wait {int(lock_duration - elapsed)} seconds or login.")
        st.stop()
    elif elapsed >= lock_duration:
        st.session_state.failed_attempts = 0

# ===== Pages =====

if choice == "Home":
    st.subheader("🏠 Welcome to the Secure Data System")
    st.write("This app allows **multi-user encrypted storage & retrieval** using strong passkeys.")

elif choice == "Store Data":
    st.subheader("📝 Store Your Secure Data")
    username = st.text_input("Enter Username:")
    text = st.text_area("Enter Data:")
    passkey = st.text_input("Enter Passkey:", type="password")

    if st.button("Encrypt & Save"):
        if username and text and passkey:
            store_user_data(username, text, passkey)
            st.success("✅ Data encrypted and saved securely.")
        else:
            st.error("⚠️ Please fill all fields!")

elif choice == "Retrieve Data":
    st.subheader("🔍 Retrieve Encrypted Data")
    username = st.text_input("Enter Username:")
    encrypted_text = st.text_area("Enter Encrypted Data:")
    passkey = st.text_input("Enter Passkey:", type="password")

    if st.button("Decrypt"):
        if username and encrypted_text and passkey:
            decrypted = retrieve_user_data(username, encrypted_text, passkey)
            if decrypted:
                st.success(f"✅ Decrypted Data: {decrypted}")
            else:
                remaining = 3 - st.session_state.failed_attempts
                st.error(f"❌ Incorrect credentials! Attempts remaining: {remaining}")
                if st.session_state.failed_attempts >= 3:
                    st.warning("🔒 Too many attempts. Redirecting to login.")
                    st.rerun()
        else:
            st.error("⚠️ All fields are required.")

elif choice == "Login":
    st.subheader("🔑 Admin Reauthorization")
    master = st.text_input("Enter Admin Password:", type="password")
    
    if st.button("Login"):
        if master == "admin123":  # Change this in production
            st.session_state.authenticated = True
            st.session_state.failed_attempts = 0
            st.success("✅ Access restored. You can now retry decryption.")
            time.sleep(1)
            st.rerun()
        else:
            st.error("❌ Invalid master password.")
