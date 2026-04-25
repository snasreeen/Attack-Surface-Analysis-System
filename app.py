"""
Attack Surface and Attack Path Analysis System
Main Flask Application
"""

from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from flask_cors import CORS
import json
import os
import re
import hashlib
import secrets
import smtplib
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from urllib.parse import urlencode
from urllib import request as urllib_request
from urllib import parse as urllib_parse
from urllib.error import URLError, HTTPError
from werkzeug.security import generate_password_hash, check_password_hash

from scanner import run_scan
from analyzer import analyze_results
from log_analysis import analyze_logs

app = Flask(__name__)
app.secret_key = "cybersec_secret_2024"
CORS(app)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
)

PASSWORD_RE = re.compile(r"^(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z0-9]).{8,}$")
OTP_TTL_MINUTES = 10

# Simple JSON-based user storage
USERS_FILE = "users.json"

def load_users():
    if not os.path.exists(USERS_FILE):
        return {}
    with open(USERS_FILE, "r") as f:
        return json.load(f)

def save_users(users):
    with open(USERS_FILE, "w") as f:
        json.dump(users, f, indent=2)

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def hash_password(password):
    return generate_password_hash(password)


def verify_password(stored_password: str, raw_password: str) -> bool:
    # Backward compatibility for legacy SHA256 users.json values.
    if stored_password.startswith("pbkdf2:") or stored_password.startswith("scrypt:"):
        return check_password_hash(stored_password, raw_password)
    return stored_password == hashlib.sha256(raw_password.encode()).hexdigest()


def password_is_strong(password: str) -> bool:
    return bool(PASSWORD_RE.match(password))


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def iso_now() -> str:
    return utc_now().isoformat()


def send_otp_email(receiver_email: str, otp: str) -> bool:
    smtp_host = os.getenv("SMTP_HOST")
    smtp_port = int(os.getenv("SMTP_PORT", "587"))
    smtp_user = os.getenv("SMTP_USER")
    smtp_pass = os.getenv("SMTP_PASS")
    smtp_from = os.getenv("SMTP_FROM", smtp_user or "no-reply@cyberscan.local")

    if not smtp_host or not smtp_user or not smtp_pass:
        print(f"[OTP] SMTP not configured. OTP for {receiver_email}: {otp}")
        return False

    msg = EmailMessage()
    msg["Subject"] = "CyberScan OTP Login Code"
    msg["From"] = smtp_from
    msg["To"] = receiver_email
    msg.set_content(
        f"Your CyberScan OTP is: {otp}\n"
        f"It expires in {OTP_TTL_MINUTES} minutes.\n"
        "If you did not request this code, ignore this email."
    )

    with smtplib.SMTP(smtp_host, smtp_port, timeout=20) as server:
        server.starttls()
        server.login(smtp_user, smtp_pass)
        server.send_message(msg)
    return True


# ─── Routes ────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/register", methods=["POST"])
def register():
    data = request.get_json() or {}
    name     = data.get("name", "").strip()
    email    = data.get("email", "").strip().lower()
    password = data.get("password", "")

    if not name or not email or not password:
        return jsonify({"success": False, "message": "All fields are required."}), 400
    if len(name) < 2:
        return jsonify({"success": False, "message": "Name must be at least 2 characters."}), 400
    if not EMAIL_RE.match(email):
        return jsonify({"success": False, "message": "Please enter a valid email address."}), 400
    if not password_is_strong(password):
        return jsonify({
            "success": False,
            "message": "Password must be 8+ chars with uppercase, number, and special character."
        }), 400

    users = load_users()
    if email in users:
        return jsonify({"success": False, "message": "Email already registered."}), 409

    users[email] = {
        "name": name,
        "email": email,
        "password": hash_password(password),
        "created_at": iso_now()
    }
    save_users(users)
    return jsonify({"success": True, "message": "Registration successful!"})


@app.route("/api/login", methods=["POST"])
def login():
    data     = request.get_json() or {}
    email    = data.get("email", "").strip().lower()
    password = data.get("password", "")

    if not email or not password:
        return jsonify({"success": False, "message": "Email and password are required."}), 400
    if not EMAIL_RE.match(email):
        return jsonify({"success": False, "message": "Please enter a valid email address."}), 400

    users = load_users()
    user  = users.get(email)

    if not user or not verify_password(user["password"], password):
        return jsonify({"success": False, "message": "Invalid credentials."}), 401

    # Upgrade legacy hashes after successful login.
    if not (user["password"].startswith("pbkdf2:") or user["password"].startswith("scrypt:")):
        user["password"] = hash_password(password)
        users[email] = user
        save_users(users)

    session["user"] = {"name": user["name"], "email": email}
    return jsonify({"success": True, "name": user["name"]})


@app.route("/api/logout", methods=["POST"])
def logout():
    session.pop("user", None)
    session.pop("otp_email", None)
    session.pop("otp_code", None)
    session.pop("otp_expires_at", None)
    session.pop("google_oauth_state", None)
    return jsonify({"success": True})


@app.route("/auth/google/start", methods=["GET"])
def google_start():
    client_id = os.getenv("GOOGLE_CLIENT_ID")
    redirect_uri = os.getenv("GOOGLE_REDIRECT_URI") or url_for("google_callback", _external=True)
    if not client_id:
        return redirect(url_for("index"))

    state = secrets.token_urlsafe(24)
    session["google_oauth_state"] = state
    query = urlencode({
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": "openid email profile",
        "state": state,
        "prompt": "select_account"
    })
    return redirect(f"https://accounts.google.com/o/oauth2/v2/auth?{query}")


@app.route("/api/auth/config", methods=["GET"])
def auth_config():
    google_configured = bool(os.getenv("GOOGLE_CLIENT_ID") and os.getenv("GOOGLE_CLIENT_SECRET"))
    smtp_configured = bool(os.getenv("SMTP_HOST") and os.getenv("SMTP_USER") and os.getenv("SMTP_PASS"))
    return jsonify({
        "google_configured": google_configured,
        "smtp_configured": smtp_configured
    })


@app.route("/auth/google/callback", methods=["GET"])
def google_callback():
    code = request.args.get("code", "")
    state = request.args.get("state", "")
    expected_state = session.get("google_oauth_state")
    session.pop("google_oauth_state", None)

    if not code or not expected_state or state != expected_state:
        return redirect(url_for("index"))

    client_id = os.getenv("GOOGLE_CLIENT_ID")
    client_secret = os.getenv("GOOGLE_CLIENT_SECRET")
    redirect_uri = os.getenv("GOOGLE_REDIRECT_URI") or url_for("google_callback", _external=True)
    if not client_id or not client_secret:
        return redirect(url_for("index"))

    token_payload = urllib_parse.urlencode({
        "code": code,
        "client_id": client_id,
        "client_secret": client_secret,
        "redirect_uri": redirect_uri,
        "grant_type": "authorization_code"
    }).encode("utf-8")
    token_req = urllib_request.Request(
        "https://oauth2.googleapis.com/token",
        data=token_payload,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST"
    )
    try:
        with urllib_request.urlopen(token_req, timeout=20) as response:
            token_data = json.loads(response.read().decode("utf-8"))
    except (HTTPError, URLError, TimeoutError, json.JSONDecodeError):
        return redirect(url_for("index"))
    access_token = token_data.get("access_token")
    if not access_token:
        return redirect(url_for("index"))

    userinfo_req = urllib_request.Request(
        "https://www.googleapis.com/oauth2/v2/userinfo",
        headers={"Authorization": f"Bearer {access_token}"}
    )
    try:
        with urllib_request.urlopen(userinfo_req, timeout=20) as response:
            profile = json.loads(response.read().decode("utf-8"))
    except (HTTPError, URLError, TimeoutError, json.JSONDecodeError):
        return redirect(url_for("index"))
    email = str(profile.get("email", "")).strip().lower()
    name = str(profile.get("name", "")).strip() or "Google User"
    if not email:
        return redirect(url_for("index"))

    users = load_users()
    user = users.get(email)
    if not user:
        users[email] = {
            "name": name,
            "email": email,
            "password": "",
            "created_at": iso_now(),
            "oauth_provider": "google"
        }
        save_users(users)
    session["user"] = {"name": name, "email": email}
    return redirect(url_for("index"))


@app.route("/api/otp/send", methods=["POST"])
def send_otp():
    data = request.get_json() or {}
    email = data.get("email", "").strip().lower()
    if not email or not EMAIL_RE.match(email):
        return jsonify({"success": False, "message": "Please enter a valid email address."}), 400

    users = load_users()
    user = users.get(email)
    if not user:
        return jsonify({"success": False, "message": "No account found for this email."}), 404

    otp = f"{secrets.randbelow(900000) + 100000}"
    session["otp_email"] = email
    session["otp_code"] = otp
    session["otp_expires_at"] = (utc_now() + timedelta(minutes=OTP_TTL_MINUTES)).isoformat()
    otp_sent_via_email = send_otp_email(email, otp)
    message = "OTP sent successfully." if otp_sent_via_email else "OTP sent (check console for demo)."
    return jsonify({"success": True, "message": message})


@app.route("/api/otp/verify", methods=["POST"])
def verify_otp():
    data = request.get_json() or {}
    email = data.get("email", "").strip().lower()
    otp = data.get("otp", "").strip()
    session_email = session.get("otp_email")
    session_otp = session.get("otp_code")
    expires_at = session.get("otp_expires_at")

    if not email or not otp:
        return jsonify({"success": False, "message": "Email and OTP are required."}), 400
    if email != session_email or otp != session_otp:
        return jsonify({"success": False, "message": "Invalid OTP."}), 401
    if not expires_at or utc_now() > datetime.fromisoformat(expires_at):
        return jsonify({"success": False, "message": "OTP expired. Request a new code."}), 401

    users = load_users()
    user = users.get(email)
    if not user:
        return jsonify({"success": False, "message": "User not found."}), 404

    session["user"] = {"name": user["name"], "email": email}
    session.pop("otp_email", None)
    session.pop("otp_code", None)
    session.pop("otp_expires_at", None)
    return jsonify({"success": True, "name": user["name"]})


@app.route("/api/scan", methods=["POST"])
def scan():
    """Main scan endpoint: runs Nmap, analyzes results, reads logs."""
    if not session.get("user"):
        return jsonify({"success": False, "message": "Unauthorized"}), 401

    data = request.get_json() or {}
    ip   = data.get("ip", "").strip()

    if not ip:
        return jsonify({"success": False, "message": "IP address is required."}), 400

    # Run port scan
    scan_data = run_scan(ip)

    # Analyze ports → vulnerabilities → MITRE ATT&CK → attack paths
    analysis = analyze_results(scan_data)

    # Analyze log files
    log_results = analyze_logs()

    # Combine and return
    response = {
        "success": True,
        "ip": ip,
        "scan": scan_data,
        "analysis": analysis,
        "logs": log_results,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    return jsonify(response)


@app.route("/api/session", methods=["GET"])
def check_session():
    user = session.get("user")
    if user:
        return jsonify({"logged_in": True, "name": user["name"]})
    return jsonify({"logged_in": False})


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)