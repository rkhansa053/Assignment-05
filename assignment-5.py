import streamlit as st
import hashlib
import json
import os
import time
from cryptography.fernet import Fernet
from base64 import urlsafe_b64encode
from hashlib import pbkdf2_hmac


DATA_FILE = "secure_data.json"
SALT = b"secure_salt_value"
LOCKOUT_TIME = 60


if "authenticated_user" not in st.session_state:
    st.session_state.authentication_user = None

if "failed_login" not in st.session_state:
    st.session_state.failed_login = 0

if "lockout_time" not in st.session_state:
    st.session_state.lockout_time = 0

# DATA LOADING CODE

def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as f:
            return json.load(f)
    return{}


def save_data(data):
    with open(DATA_FILE, "w") as f:
        json.dump(data, f)


def generatekey(passkey):
    key = pbkdf2_hmac('sha256' , passkey.encode(), SALT, 100000)
    return urlsafe_b64encode(key)


def hash_password(password):
    return hashlib.pbkdf2_hmac('sha256' , password.encode(), SALT, 100000).hex()


# USE OF CRYPTOGRAPHY FERNET

def encrypt_text(text, key):
    cipher = Fernet(generatekey(key))
    return cipher.encrypt(text.encode()).decode()

def decrypt(encrypt_text, key):
    try:
        cipher = Fernet(generatekey(key))
        return cipher.decrypt(encrypt_text.encode()).decode()
    except:
        return None 
    

stored_data = load_data()

# NAVIGATION CODE

st.title(" 🔒 Secure Data Encryption System Using Streamlit")
menu = ["Home","Register","Login","Store Data","Retrieve Data"]
choice = st.sidebar.selectbox("Navigation", menu)


if choice == "Home":
    st.subheader("Welcome to Data Encryption System!")
    st.markdown("Use this app to **securely store and retrieve data** using unique passkeys.")


# REGISTRATION CODE

elif choice == "Register":
    st.subheader("✍ Register new user")
    username = st.text_input("Enter username: ")
    password = st.text_input("Enter strong password: ", type= "password")


    if st.button("Register"):
        if username and password:
            if username in stored_data:
                st.warning("⚠ User already exist.")
            else:
                stored_data[username] = {
                    "password": hash_password(password),
                    "data": []
                }
                save_data(stored_data)
                st.success("✅User register successfully!")   
        else:
            st.error("Both fields are required.")
elif choice == "Login":
        st.subheader("🔑 User Login")

        if time.time() < st.session_state.lockout_time:
            remaining = int(st.session_state.lockout_time - time.time())
            st.error(f" ⏱ Too many failed attempts. Please wait {remaining} seconds.")  
            st.stop()

        username = st.text_input("Username")
        password = st.text_input("Password", type= "password")

        if st.button("Login"):
            if username in stored_data and stored_data[username]["password"] == hash_password(password):
                st.session_state.authenticated_user = username
                st.session_state.failed_login = 0
                st.success(f"😊 Welcome {username}!")
            else:
                st.session_state.failed_login += 1
                remaining = 3 - st.session_state.failed_login
                st.error(f"❌ Invalid Credentials! Attempts left: {remaining}")

                if st.session_state.failed_login >= 3:
                    st.session_state.lockout_time = time.time() + LOCKOUT_TIME
                    st.error("🔴To many attempts. Locked for 60 seconds")
                    st.stop()


# DATA STORE CODE

elif choice == "Store Data":
    if not st.session_state.authenticated_user:
        st.warning("🔒 Please login first.")
    else:
        st.subheader("Store Encrypted Data")
        data = st.text_area("Enter data to encrypt")
        passkey = st.text_input("Encryption key (passphrase)", type="password")
        if st.button("Encrypt And Save"):
            if data and passkey:
                encrypted = encrypt_text(data, passkey)
                stored_data[st.session_state.authenticated_user]["data"].append(encrypted)  
                save_data(stored_data)
                st.success("✅Data encrypted and save successfully!")
            else:
                st.error("All fields are required to fill.")

# RETRIEVE DATA CODE                

elif choice == "Retrieve Data":
    if not st.session_state.authenticated_user:
        st.warning("Please login first")
    else:
        st.subheader("🔍 Retrieve Data")
        user_data = stored_data.get(st.session_state.authenticated_user, {}).get("data", [])        
        if not user_data:
            st.info("No data found!")
        else:
            st.write("Encrypted Data Enteries:")
            for i, item in enumerate(user_data):
                st.code(item,language="text")

            encrypt_input = st.text_area("Enter Encrypted text")
            passkey = st.text_input("Enter Passkey To Decrypt", type="password") 
                   
            if st.button("Decrypt"):
                result = encrypt_text(encrypt_input, passkey)
                if result:
                    st.success(f"✅Decrypted : {result}")
                else:
                    st.error("❌ Incorret passkey or corrupted data!")    