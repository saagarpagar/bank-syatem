# bank-syatem
import streamlit as st
import smtplib, ssl, random, string, hashlib
from datetime import datetime

def generate_otp(length=6):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

def send_email_otp(receiver_email, otp):
    sender_email = "your_email@gmail.com"
    sender_password = "your_app_password"
    subject = "OTP Verification"
    body = f"Your OTP is: {otp}"
    message = f"Subject: {subject}\n\n{body}"
    context = ssl.create_default_context()
    with smtplib.SMTP_SSL("smtp.gmail.com", 465, context=context) as server:
        server.login(sender_email, sender_password)
        server.sendmail(sender_email, receiver_email, message)

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

if 'users' not in st.session_state:
    st.session_state.users = {}

if 'current_user' not in st.session_state:
    st.session_state.current_user = None

if 'otp' not in st.session_state:
    st.session_state.otp = None

if 'transactions' not in st.session_state:
    st.session_state.transactions = {}

st.title("💰 Banking Web App with Login & OTP")

menu = st.sidebar.selectbox("Menu", ["Login", "Sign Up", "Dashboard", "Logout"])

if menu == "Sign Up":
    st.subheader("Create New Account")
    name = st.text_input("Name")
    email = st.text_input("Email")
    password = st.text_input("Password", type="password")
    if st.button("Send OTP"):
        if name and email and password:
            st.session_state.otp = generate_otp()
            st.session_state.pending_user = (name, email, hash_password(password))
            send_email_otp(email, st.session_state.otp)
            st.success("OTP sent to your email.")
    if st.session_state.otp:
        user_otp = st.text_input("Enter OTP")
        if st.button("Verify OTP"):
            if user_otp == st.session_state.otp:
                name, email, hashed_pw = st.session_state.pending_user
                st.session_state.users[email] = {
                    "name": name,
                    "password": hashed_pw,
                    "balance": 1000,
                    "history": []
                }
                st.success("Account created successfully. Please login.")
                st.session_state.otp = None
            else:
                st.error("Invalid OTP.")

if menu == "Login":
    st.subheader("Login to Your Account")
    email = st.text_input("Email", key="login_email")
    password = st.text_input("Password", type="password", key="login_pw")
    if st.button("Login"):
        if email in st.session_state.users:
            hashed = hash_password(password)
            if st.session_state.users[email]["password"] == hashed:
                st.session_state.current_user = email
                st.success("Logged in successfully.")
            else:
                st.error("Incorrect password.")
        else:
            st.error("Account not found.")

if menu == "Dashboard":
    if st.session_state.current_user:
        user_data = st.session_state.users[st.session_state.current_user]
        st.subheader(f"Welcome, {user_data['name']}")
        st.write(f"Balance: ₹{user_data['balance']}")
        action = st.selectbox("Choose Action", ["Credit", "Debit", "View History"])
        if action == "Credit":
            amount = st.number_input("Amount to credit", min_value=1)
            if st.button("Credit"):
                user_data["balance"] += amount
                user_data["history"].append((datetime.now(), f"+₹{amount}"))
                st.success(f"₹{amount} credited.")
        elif action == "Debit":
            amount = st.number_input("Amount to debit", min_value=1)
            if st.button("Debit"):
                if amount <= user_data["balance"]:
                    user_data["balance"] -= amount
                    user_data["history"].append((datetime.now(), f"-₹{amount}"))
                    st.success(f"₹{amount} debited.")
                else:
                    st.error("Insufficient balance.")
        elif action == "View History":
            st.subheader("Transaction History")
            for time, entry in reversed(user_data["history"]):
                st.write(f"{time.strftime('%d-%m-%Y %H:%M:%S')} — {entry}")
    else:
        st.warning("Login to view dashboard.")

if menu == "Logout":
    if st.session_state.current_user:
        st.session_state.current_user = None
        st.success("Logged out successfully.")
    else:
        st.info("No user is currently logged in.")
