import streamlit as st
import hashlib
import time
from cryptography.fernet import Fernet

# ------------------------------------------------------
# Generate (once) and persist the encryption key
if 'fernet_key' not in st.session_state:
    st.session_state.fernet_key = Fernet.generate_key()
cipher_suite = Fernet(st.session_state.fernet_key)

# ------------------------------------------------------
# Initialize session state for data + attempts
if 'stored_data' not in st.session_state:
    st.session_state.stored_data = {}
if 'failed_attempts' not in st.session_state:
    st.session_state.failed_attempts = 0

# ------------------------------------------------------
# Security configurations
MAX_ATTEMPTS = 3
MASTER_PASSWORD_HASH = hashlib.sha256("admin123".encode()).hexdigest()

# ------------------------------------------------------
# Helpers
def hash_passkey(passkey: str) -> str:
    return hashlib.sha256(passkey.encode()).hexdigest()

def encrypt_data(plain_text: str) -> str:
    return cipher_suite.encrypt(plain_text.encode()).decode()

def decrypt_data(encrypted_text: str) -> str:
    try:
        return cipher_suite.decrypt(encrypted_text.encode()).decode()
    except Exception:
        # Covers InvalidToken and others
        return None

def safe_rerun():
    try:
        st.rerun()
    except AttributeError:
        st.experimental_rerun()

# ------------------------------------------------------
# Login / reauthorization
def show_login_page():
    st.subheader("🔑 Reauthorization Required")
    login_password = st.text_input("Enter Master Password:", type="password")
    if st.button("Login"):
        if hashlib.sha256(login_password.encode()).hexdigest() == MASTER_PASSWORD_HASH:
            st.session_state.failed_attempts = 0
            st.success("✅ Reauthorized successfully! Redirecting...")
            time.sleep(1)
            safe_rerun()
        else:
            st.error("❌ Incorrect master password!")
    st.stop()

# ------------------------------------------------------
# Main layout
st.title("🔒 Secure Data Encryption System")
menu_choice = st.sidebar.selectbox("Navigation", ["Home", "Store Data", "Retrieve Data", "Login"])

if menu_choice == "Home":
    st.subheader("🏠 Welcome to the Secure Data System")
    st.markdown("""
        ### System Features:
        - **Secure Storage**: Encrypt data with military-grade encryption  
        - **Passkey Protection**: Data access requires unique passkeys  
        - **Brute Force Protection**: Account lock after 3 failed attempts  
        - **Memory-Resident**: No data persistence between sessions  
    """)

elif menu_choice == "Store Data":
    st.subheader("📦 Store New Data")
    with st.form("store_form"):
        data_name = st.text_input("Unique Data Name:")
        secret_text = st.text_area("Data to Encrypt:")
        passkey = st.text_input("Encryption Passkey:", type="password")
        if st.form_submit_button("Encrypt & Store"):
            if not (data_name and secret_text and passkey):
                st.error("❌ All fields are required!")
            elif data_name in st.session_state.stored_data:
                st.error("⚠️ Data name already exists! Use unique names.")
            else:
                st.session_state.stored_data[data_name] = {
                    "encrypted_text": encrypt_data(secret_text),
                    "passkey_hash": hash_passkey(passkey)
                }
                st.success("✅ Data encrypted and stored securely!")

elif menu_choice == "Retrieve Data":
    if st.session_state.failed_attempts >= MAX_ATTEMPTS:
        st.warning("🔒 Account locked! Complete reauthorization to continue.")
        show_login_page()
    else:
        st.subheader("🔍 Retrieve Stored Data")
        with st.form("retrieve_form"):
            data_name = st.text_input("Enter Stored Data Name:")
            passkey = st.text_input("Enter Passkey:", type="password")
            if st.form_submit_button("Decrypt Data"):
                if not (data_name and passkey):
                    st.error("❌ Both fields are required!")
                elif data_name not in st.session_state.stored_data:
                    st.error("❌ Data not found! Verify data name.")
                else:
                    entry = st.session_state.stored_data[data_name]
                    if hash_passkey(passkey) == entry["passkey_hash"]:
                        decrypted = decrypt_data(entry["encrypted_text"])
                        if decrypted is None:
                            st.error("❌ Decryption failed (data may be corrupted).")
                        else:
                            st.session_state.failed_attempts = 0
                            st.success(f"🔓 Decrypted Data:\n\n{decrypted}")
                    else:
                        st.session_state.failed_attempts += 1
                        remaining = MAX_ATTEMPTS - st.session_state.failed_attempts
                        st.error(f"❌ Invalid passkey! {remaining} attempts remaining")
                        if st.session_state.failed_attempts >= MAX_ATTEMPTS:
                            st.warning("🔒 Maximum attempts reached! Redirecting...")
                            time.sleep(1)
                            safe_rerun()

elif menu_choice == "Login":
    show_login_page()
