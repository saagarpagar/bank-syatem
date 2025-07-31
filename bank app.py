import streamlit as st
import smtplib
import ssl
import random
import string
import hashlib
import os
from datetime import datetime, timedelta

# --- Helper Functions ---

def generate_otp(length=6):
    return ''.join(random.choices(string.digits, k=length))  # Only digits for OTP

def send_email_otp(receiver_email, otp):
    sender_email = os.getenv("EMAIL_ADDRESS")
    sender_password = os.getenv("EMAIL_APP_PASSWORD")
    
    if not sender_email or not sender_password:
        st.error("Email configuration missing. Check environment variables.")
        return False

    subject = "OTP Verification for Banking App"
    body = f"Your OTP is: {otp}\nIt is valid for 5 minutes."
    message = f"Subject: {subject}\n\n{body}"

    try:
        context = ssl.create_default_context()
        with smtplib.SMTP_SSL("smtp.gmail.com", 465, context=context) as server:
            server.login(sender_email, sender_password)
            server.sendmail(sender_email, receiver_email, message)
        return True
    except Exception as e:
        st.error(f"Failed to send email: {e}")
        return False

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# --- Initialize Session State ---
if 'users' not in st.session_state:
    st.session_state.users = {}

if 'current_user' not in st.session_state:
    st.session_state.current_user = None

if 'otp_data' not in st.session_state:
    st.session_state.otp_data = None  # Will store: {"otp": str, "email": str, "expires": datetime}

if 'transactions' not in st.session_state:
    st.session_state.transactions = {}  # Not used directly; part of user data

# --- App Title ---
st.title("💰 Secure Banking Web App")

menu = st.sidebar.selectbox("Menu", ["Login", "Sign Up", "Dashboard", "Logout"])

# --- Sign Up ---
if menu == "Sign Up":
    st.subheader("🔐 Create New Account")
    name = st.text_input("Full Name")
    email = st.text_input("Email Address")
    password = st.text_input("Password", type="password")
    confirm_password = st.text_input("Confirm Password", type="password")

    if st.button("Send OTP"):
        if not name or not email or not password:
            st.error("Please fill all fields.")
        elif password != confirm_password:
            st.error("Passwords do not match.")
        elif len(password) < 6:
            st.error("Password must be at least 6 characters.")
        elif email in st.session_state.users:
            st.error("An account with this email already exists.")
        else:
            otp = generate_otp()
            expires_at = datetime.now() + timedelta(minutes=5)
            st.session_state.otp_data = {
                "otp": otp,
                "email": email,
                "name": name,
                "password": hash_password(password),
                "expires": expires_at
            }
            if send_email_otp(email, otp):
                st.success(f"OTP sent to {email}. It will expire in 5 minutes.")
            else:
                st.error("Could not send OTP. Contact admin.")

    # OTP Verification
    if st.session_state.otp_data:
        entered_otp = st.text_input("Enter the OTP sent to your email", max_chars=6)
        if st.button("Verify & Complete Sign Up"):
            otp_record = st.session_state.otp_data
            if datetime.now() > otp_record["expires"]:
                st.error("OTP has expired. Please request a new one.")
                st.session_state.otp_data = None
            elif entered_otp == otp_record["otp"]:
                # Save user
                st.session_state.users[otp_record["email"]] = {
                    "name": otp_record["name"],
                    "password": otp_record["password"],
                    "balance": 1000.0,
                    "history": [(datetime.now(), "Account created with ₹1000 initial balance")]
                }
                st.success("✅ Account created successfully! You can now log in.")
                st.session_state.otp_data = None  # Clear OTP after use
            else:
                st.error("❌ Invalid OTP.")

# --- Login ---
if menu == "Login":
    st.subheader("🔑 Login to Your Account")
    email = st.text_input("Email Address", key="login_email")
    password = st.text_input("Password", type="password", key="login_password")

    if st.button("Login"):
        if email in st.session_state.users:
            hashed_pw = hash_password(password)
            if st.session_state.users[email]["password"] == hashed_pw:
                st.session_state.current_user = email
                st.success(f"Welcome back, {st.session_state.users[email]['name']}!")
            else:
                st.error("❌ Incorrect password.")
        else:
            st.error("❌ No account found with that email.")

# --- Dashboard ---
if menu == "Dashboard":
    if st.session_state.current_user:
        user = st.session_state.users[st.session_state.current_user]
        st.subheader(f"🏠 Dashboard - {user['name']}")
        st.metric("Current Balance", f"₹{user['balance']:.2f}")

        action = st.selectbox("Choose an action:", ["📥 Credit", "📤 Debit", "📋 View Transaction History"])

        if action == "📥 Credit":
            amount = st.number_input("Enter amount to credit:", min_value=1.0, step=1.0)
            if st.button("Add Funds"):
                if amount > 0:
                    user["balance"] += amount
                    user["history"].append((datetime.now(), f"📥 Credited ₹{amount:.2f}"))
                    st.success(f"₹{amount:.2f} credited successfully!")

        elif action == "📤 Debit":
            amount = st.number_input("Enter amount to debit:", min_value=1.0, step=1.0)
            if st.button("Withdraw"):
                if amount > user["balance"]:
                    st.error("❌ Insufficient balance!")
                elif amount > 0:
                    user["balance"] -= amount
                    user["history"].append((datetime.now(), f"📤 Debited ₹{amount:.2f}"))
                    st.success(f"₹{amount:.2f} withdrawn successfully!")

        elif action == "📋 View Transaction History":
            st.markdown("### 📜 Transaction History")
            if user["history"]:
                for timestamp, desc in reversed(user["history"]):
                    st.text(f"{timestamp.strftime('%d %b, %Y %I:%M %p')} → {desc}")
            else:
                st.info("No transactions yet.")

    else:
        st.warning("Please log in to access the dashboard.")
        st.info("Go to **Login** from the sidebar.")

# --- Logout ---
if menu == "Logout":
    if st.session_state.current_user:
        name = st.session_state.users[st.session_state.current_user]["name"]
        st.session_state.current_user = None
        st.success(f"👋 {name}, you've been logged out successfully.")
    else:
        st.info("You are not logged in.")
