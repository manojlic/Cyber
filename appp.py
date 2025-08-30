import streamlit as st
import re
import cv2
import numpy as np
from PIL import Image
from urllib.parse import urlparse, parse_qs
import Levenshtein
import io
import datetime as dt

# =====================
# Config / Constants
# =====================
SAFE_HANDLES = {
    # Common UPI handles
    "upi", "ybl", "okhdfcbank", "okaxis", "okicici", "oksbi", "okyesbank",
    "okkotak", "okboi", "okpnb", "okidfc", "okdbs", "oksbp", "ibl",
    "apl", "axl", "paytm", "ibl", "idfcbank", "uaxis", "aubank"
}

SUSPICIOUS_KEYWORDS = {
    "pmcare", "pmcares", "lottery", "win", "winmoney", "prize",
    "donation", "grant", "govfund", "reward", "cashbackgift"
}

SIMILARITY_THRESHOLD = 0.85

BLACKLIST_FILE = "blacklist.txt"

# =====================
# Utilities
# =====================
@st.cache_data(show_spinner=False)
def load_blacklist(path: str = BLACKLIST_FILE):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return sorted({line.strip().lower() for line in f if line.strip()})
    except FileNotFoundError:
        return []


def save_blacklist(items, path: str = BLACKLIST_FILE):
    # No cache invalidation here; caller should clear cache
    with open(path, "w", encoding="utf-8") as f:
        for x in sorted(set(i.lower().strip() for i in items if i.strip())):
            f.write(x + "\n")


def is_valid_upi_format(upi_id: str) -> bool:
    return bool(re.match(r"^[a-zA-Z0-9.\-_]+@[a-zA-Z]+$", upi_id))


def get_handle(upi_id: str) -> str:
    try:
        return upi_id.split("@", 1)[1]
    except Exception:
        return ""


def is_allowed_handle(upi_id: str) -> bool:
    return get_handle(upi_id).lower() in SAFE_HANDLES


def looks_like_url(text: str) -> bool:
    p = urlparse(text)
    return bool(p.scheme and p.netloc)


SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "rb.gy", "t.co", "is.gd", "cutt.ly", "goo.gl",
    "rebrand.ly", "ow.ly", "s.id", "shorturl.at"
}


def is_shortened(url: str) -> bool:
    netloc = urlparse(url).netloc.lower()
    return any(netloc.endswith(dom) for dom in SHORTENER_DOMAINS)


def extract_upi_from_qrtext(qr_text: str):
    """Return (upi_id, parsed_url) or (None, None). Accepts upi://pay or raw UPI."""
    text = qr_text.strip()
    if is_valid_upi_format(text):
        return text.lower(), None

    if looks_like_url(text):
        p = urlparse(text)
        if p.scheme.lower().startswith("upi"):
            qs = parse_qs(p.query)
            pa = qs.get("pa", [""])[0].lower().strip()
            if is_valid_upi_format(pa):
                return pa, text
        # Not a UPI link; may be a regular URL embedded in QR
        return None, text

    # Try to find pa= inside arbitrary text
    m = re.search(r"pa=([a-zA-Z0-9.\-_]+@[a-zA-Z]+)", text)
    if m:
        return m.group(1).lower(), None
    return None, None


# =============== QR Decoder (OpenCV) ===============

def decode_qr_image(file) -> str | None:
    """Decode a QR code image using OpenCV. Returns text or None."""
    image = Image.open(file).convert("RGB")
    img_np = np.array(image)
    detector = cv2.QRCodeDetector()
    data, bbox, _ = detector.detectAndDecode(img_np)
    return data if data else None


# =============== Core Checks ===============

def similarity_to_blacklist(upi_id: str, blacklist: list[str]):
    best = (None, 0.0)
    for bad in blacklist:
        r = Levenshtein.ratio(upi_id, bad)
        if r > best[1]:
            best = (bad, r)
    return best  # (closest, score)


def analyze_upi(upi_id: str, blacklist: list[str]):
    upi_id = upi_id.lower().strip()

    if not is_valid_upi_format(upi_id):
        return {
            "status": "invalid",
            "reason": "Invalid UPI format",
            "details": f"Does not match name@bank format: {upi_id}",
        }

    if upi_id in blacklist:
        return {"status": "danger", "reason": "Blacklisted", "details": upi_id}

    # Suspicious keywords
    for kw in SUSPICIOUS_KEYWORDS:
        if kw in upi_id:
            return {
                "status": "danger",
                "reason": "Suspicious keyword",
                "details": f"Found '{kw}' in {upi_id}",
            }

    # Handle allow-list
    if not is_allowed_handle(upi_id):
        return {
            "status": "warning",
            "reason": "Unknown handle",
            "details": f"Handle @{get_handle(upi_id)} not in common providers",
        }

    # Similarity check
    closest, score = similarity_to_blacklist(upi_id, blacklist)
    if closest and score >= SIMILARITY_THRESHOLD:
        return {
            "status": "danger",
            "reason": "Similar to blacklisted",
            "details": f"{upi_id} ≈ {closest} (score {score:.2f})",
        }

    return {"status": "safe", "reason": "Passed all checks", "details": upi_id}


# =============== UI ===============
st.set_page_config(page_title="UPI & QR Scam Detector", page_icon="🛡️", layout="centered")

st.title("🛡️ UPI & QR Scam Detector")
st.caption("Scan a QR or paste a UPI/payment link. We'll flag risky patterns.")

# Sidebar
with st.sidebar:
    st.subheader("Settings")
    st.write("Similarity threshold (to flag near-clones of blacklisted IDs)")
    thr = st.slider("Similarity", 0.70, 0.99, SIMILARITY_THRESHOLD, 0.01)
    if thr != SIMILARITY_THRESHOLD:
        SIMILARITY_THRESHOLD = thr
    st.divider()
    st.subheader("About")
    st.markdown(
        """
        **Checks performed**
        - Format validation (name@bank)
        - Blacklist lookup
        - Suspicious keywords
        - Allowed handle list
        - Similarity to blacklisted IDs
        - URL safety (shorteners / non-UPI links)
        """
    )

# Load blacklist (cached)
blacklist = load_blacklist()

# Session state for history
if "history" not in st.session_state:
    st.session_state.history = []

# Inputs
col1, col2 = st.columns(2)
with col1:
    user_input = st.text_input(
        "Paste UPI ID or URL (upi://pay?... or https://...)",
        placeholder="example: user@upi OR upi://pay?pa=user@upi",
    )
with col2:
    qr_file = st.file_uploader("Or upload a QR image", type=["png", "jpg", "jpeg"])

extracted_upi = None
source_text = None

# Handle QR
if qr_file is not None:
    qr_text = decode_qr_image(qr_file)
    if qr_text:
        st.info(f"📷 QR content: {qr_text}")
        upi_from_qr, url_from_qr = extract_upi_from_qrtext(qr_text)
        extracted_upi = upi_from_qr
        source_text = url_from_qr or qr_text
        if extracted_upi:
            st.success(f"Extracted UPI: {extracted_upi}")
        else:
            st.warning("QR did not contain a valid UPI ID. If it is a URL, proceed with caution.")
    else:
        st.error("No QR detected in the image.")

# Determine target for check
target_text = extracted_upi or user_input.strip()

# URL safety quick check
url_flag = None
if target_text and looks_like_url(target_text) and not target_text.lower().startswith("upi"):
    if is_shortened(target_text):
        url_flag = ("warning", "Shortened link detected. Could be hiding destination.")
    else:
        url_flag = ("warning", "Non‑UPI URL inside QR/text. Verify before proceeding.")

# Action
if st.button("Check Safety", type="primary"):
    if not target_text:
        st.warning("Please provide a UPI ID or upload a QR image.")
    else:
        # If it's a URL, try to extract UPI from it
        upi_from_text, parsed_url = extract_upi_from_qrtext(target_text)
        checked_upi = upi_from_text or (target_text if is_valid_upi_format(target_text) else None)

        record = {
            "time": dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "input": target_text,
            "upi": checked_upi or "",
        }

        if url_flag:
            level, msg = url_flag
            st.warning(f"🌐 {msg}")
            record["url_flag"] = msg

        if checked_upi:
            res = analyze_upi(checked_upi, blacklist)
            record.update(res)

            if res["status"] == "safe":
                st.success(f"✅ Safe UPI: {checked_upi}")
            elif res["status"] == "warning":
                st.warning(f"⚠️ {res['reason']}: {res['details']}")
            elif res["status"] == "danger":
                st.error(f"🛑 {res['reason']}: {res['details']}")
            else:
                st.info(f"ℹ️ {res['reason']}: {res['details']}")
        else:
            # Not a UPI ID we can analyze
            record.update({"status": "unknown", "reason": "No UPI found", "details": target_text})
            st.info("Could not extract a valid UPI ID to analyze.")

        st.session_state.history.append(record)

st.divider()

# History Table
if st.session_state.history:
    st.subheader("Scan History (this session)")
    st.dataframe(st.session_state.history, use_container_width=True)
    # Download CSV
    import pandas as pd
    df = pd.DataFrame(st.session_state.history)
    csv = df.to_csv(index=False).encode("utf-8")
    st.download_button("Download history CSV", data=csv, file_name="scan_history.csv", mime="text/csv")

st.divider()

# Report / Manage Blacklist
with st.expander("Report a suspicious UPI to blacklist"):
    new_bad = st.text_input("UPI to add to blacklist", placeholder="scam-example@upi")
    if st.button("Add to blacklist"):
        if is_valid_upi_format(new_bad):
            items = set(load_blacklist())
            items.add(new_bad.lower())
            save_blacklist(items)
            load_blacklist.clear()  # clear cache
            st.success(f"Added {new_bad} to blacklist. Restart app to refresh cache if needed.")
        else:
            st.error("Please enter a valid UPI in name@bank format.")

with st.expander("View current blacklist"):
    bl = load_blacklist()
    if bl:
        st.code("\n".join(bl), language="text")
    else:
        st.info("Blacklist is empty.")
