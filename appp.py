import streamlit as st
import re
import Levenshtein
import os

# Suspicious keywords
KEYWORDS = ["pmcare", "pmcares", "lottery", "winmoney", "prize", "donation"]

# ---------------- FILE HANDLING ----------------
def load_blacklist(filepath="blacklist.txt"):
    try:
        with open(filepath, "r") as f:
            return [line.strip().lower() for line in f if line.strip()]
    except FileNotFoundError:
        return []

def block_upi(upi_id: str, filepath="blacklist.txt"):
    with open(filepath, "a") as f:
        f.write(upi_id.lower().strip() + "\n")

def log_checked_upi(upi_id: str, result: str, logfile="logs.txt"):
    with open(logfile, "a") as f:
        f.write(f"{upi_id} | {result}\n")

def load_logs(logfile="logs.txt"):
    if not os.path.exists(logfile):
        return []
    with open(logfile, "r") as f:
        return [line.split("|")[0].strip() for line in f if line.strip()]

BLACKLIST = load_blacklist()

# ---------------- UPI VALIDATION ----------------
def is_valid_format(upi_id: str) -> bool:
    """Check if UPI matches standard format: name@bank"""
    return bool(re.match(r"^[a-zA-Z0-9.\-_]+@[a-zA-Z]+$", upi_id))

def check_similarity(upi_id: str, threshold=0.85):
    """Check if UPI ID is very similar to a known blacklist entry"""
    for black in BLACKLIST:
        ratio = Levenshtein.ratio(upi_id, black)
        if ratio >= threshold:
            return black, ratio
    return None, 0

def check_upi_id(upi_id: str) -> str:
    upi_id = upi_id.lower().strip()

    # 1. Format check
    if not is_valid_format(upi_id):
        return f"❌ Invalid UPI format: {upi_id}"

    # 2. Direct blacklist check
    if upi_id in BLACKLIST:
        return f"⚠️ Blacklisted UPI ID: {upi_id}"

    # 3. Keyword-based detection
    for kw in KEYWORDS:
        if kw in upi_id:
            return f"⚠️ Suspicious keyword '{kw}' found in {upi_id}"

    # 4. Similarity check
    similar, score = check_similarity(upi_id)
    if similar:
        return f"⚠️ UPI ID '{upi_id}' looks similar to blacklisted '{similar}' (score: {score:.2f})"

    return f"✅ Safe UPI ID: {upi_id}"

# ---------------- STREAMLIT APP ----------------
st.title("🔐 UPI Scam Detector")
st.write("Check if a UPI ID looks suspicious or safe")

# Load past logs for dropdown
previous_logs = load_logs()

# Input section
upi_input = st.text_input("Enter a UPI ID:")

# Dropdown of previously checked IDs
if previous_logs:
    selected = st.selectbox("Or select from previously checked IDs:", ["--Select--"] + previous_logs)
    if selected != "--Select--":
        upi_input = selected

# Check button
if st.button("Check"):
    if upi_input:
        result = check_upi_id(upi_input)
        log_checked_upi(upi_input, result)  # log search
        st.success(result) if "✅" in result else st.error(result)
    else:
        st.warning("Please enter a UPI ID first.")

# Block button
if st.button("Block this UPI ID"):
    if upi_input:
        block_upi(upi_input)
        st.success(f"{upi_input} has been blocked ✅")
    else:
        st.warning("Please enter a UPI ID first.")
