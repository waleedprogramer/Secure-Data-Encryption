import streamlit as st
import os
import json
import hashlib
import base64
from cryptography.fernet import Fernet

# --- Page config & styles ---
st.set_page_config(page_title="Secure Data App", layout="centered")

st.markdown("""
    <style>
        body, .main { background-color: #f8f9fa; }
        h1, h2, h3 { color: #343a40; font-family: sans-serif; }
        .stButton>button {
            background-color: #198754;
            color: white;
            padding: 0.5em 1em;
            border-radius: 5px;
        }
       .home-h1{
            text-align: center; 
            color: #198754;
            }
        .home-p{
            text-align: center; 
            color: #495057; 
            font-size: 16px;
            }
    </style>
""", unsafe_allow_html=True)



# --- Utility functions ---
def derive_key(pass_key, salt):
    key = hashlib.pbkdf2_hmac("sha256", pass_key.encode(), salt, 100_000)
    return base64.urlsafe_b64encode(key)

def hash_password(password, salt):
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100_000).hex()

def save_user(email, password):
    salt = os.urandom(16)
    hashed = hash_password(password, salt)
    user_data = {
        "email": email,
        "password": hashed,
        "salt": salt.hex()
    }
    try:
        with open("login_data.json", "r") as f:
            users = json.load(f)
    except FileNotFoundError:
        users = []

    if any(u["email"] == email for u in users):
        return False

    users.append(user_data)
    with open("login_data.json", "w") as f:
        json.dump(users, f, indent=4)
    return True

def check_login(email, password):
    try:
        with open("login_data.json", "r") as f:
            users = json.load(f)
    except FileNotFoundError:
        return False

    for user in users:
        if user["email"] == email:
            salt = bytes.fromhex(user["salt"])
            hashed = hash_password(password, salt)
            return hashed == user["password"]
    return False


# --- Pages ---
def register():
    st.subheader("Create an Account")
    with st.form("register_form"):
        email = st.text_input("Email")
        password = st.text_input("Password", type="password")
        submitted = st.form_submit_button("Register")

        if submitted:
            if len(password) < 8:
                st.error("Password must be at least 8 characters long.")
            elif not email:
                st.error("Please enter an email.")
            elif save_user(email, password):
                st.success("Registration successful. You can now log in.")
            else:
                st.warning("This email is already registered.")

def login():
    st.subheader("Login to Your Account")
    with st.form("login_form"):
        email = st.text_input("Email")
        password = st.text_input("Password", type="password")
        submitted = st.form_submit_button("Login")

        if submitted:
            if check_login(email, password):
                st.session_state.logged_in = True
                st.session_state.user_email = email
                st.success(f"Welcome, {email}!")
            else:
                st.error("Invalid email or password.")

def encrypt_decrypt():
    st.subheader("Encrypt or Decrypt Data")

    operation = st.radio("Choose", ["Encrypt", "Decrypt"])

    if operation == "Encrypt":
        text = st.text_area("Text to Encrypt")
        key = st.text_input("Encryption Key", type="password")
        if st.button("Encrypt and Save"):
            if text and key:
                salt = os.urandom(16)
                derived_key = derive_key(key, salt)
                f = Fernet(derived_key)
                encrypted_text = f.encrypt(text.encode()).decode()
                data = {"text": encrypted_text, "salt": salt.hex(), "user": st.session_state.user_email}
                try:
                    with open("encrypted_data.json", "r") as f:
                        all_data = json.load(f)
                except FileNotFoundError:
                    all_data = []
                all_data.append(data)
                with open("encrypted_data.json", "w") as f:
                    json.dump(all_data, f, indent=4)
                st.success("Encrypted and saved successfully.")
            else:
                st.warning("Please enter both text and a key.")

    elif operation == "Decrypt":
        try:
            with open("encrypted_data.json", "r") as f:
                all_data = json.load(f)
        except FileNotFoundError:
            st.info("No encrypted data found.")
            return

        user_data = [item for item in all_data if item["user"] == st.session_state.user_email]
        if not user_data:
            st.info("You don’t have any encrypted entries.")
            return

        selected_index = st.selectbox(
            "Choose entry", range(len(user_data)),
            format_func=lambda i: f"Entry {i+1}: {user_data[i]['text'][:20]}..."
        )
        selected_entry = user_data[selected_index]
        key = st.text_input("Decryption Key", type="password")
        if st.button("Decrypt"):
            if key:
                salt = bytes.fromhex(selected_entry["salt"])
                derived_key = derive_key(key, salt)
                f = Fernet(derived_key)
                try:
                    decrypted_text = f.decrypt(selected_entry["text"].encode()).decode()
                    st.success(f"Decrypted Text:\n\n{decrypted_text}")
                except:
                    st.error("Invalid key or corrupted data.")
            else:
                st.warning("Enter the decryption key.")

def home():
    st.markdown("""
        <h2 class='home-h1'>🔐 Secure Data Encryption</h2>
        <p class='home-p'>
            Encrypt and decrypt your text securely and privately.
        </p>
        <hr>
    """, unsafe_allow_html=True)

    st.markdown("""
    ### 🔧 What You Can Do:
    - Register and log in securely  
    - Encrypt your sensitive text  
    - Decrypt it whenever you need  
    - Only you can see your saved entries  

    ---
    👉 Use the **sidebar** to begin!
    """)

    st.markdown("""
        <div style='text-align: center; margin-top: 20px; color: #6c757d;'>
            <em>Privacy made simple.</em>
        </div>
    """, unsafe_allow_html=True)


# --- Navigation ---
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
if "user_email" not in st.session_state:
    st.session_state.user_email = ""

st.sidebar.title("Menu")
menu = ["Home", "Register", "Login"]
if st.session_state.logged_in:
    menu += ["Encrypt/Decrypt", "Logout"]

choice = st.sidebar.selectbox("Navigate to:", menu)

if choice == "Home":
    home()
elif choice == "Register":
    register()
elif choice == "Login":
    login()
elif choice == "Encrypt/Decrypt":
    if st.session_state.logged_in:
        encrypt_decrypt()
    else:
        st.error("Please log in first.")
elif choice == "Logout":
    st.session_state.logged_in = False
    st.session_state.user_email = ""
    st.success("You’ve been logged out.")
