# fullauth.py
# Run: uvicorn fullauth:app --reload

from fastapi import FastAPI, Request, Form, Depends, Cookie
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.security import OAuth2PasswordBearer
from pymongo import MongoClient
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta
from dotenv import load_dotenv
import smtplib
from email.message import EmailMessage
import os
import random

# ================= INIT =================

load_dotenv()
app = FastAPI()

MONGO_URL = os.getenv("MONGO_URL")
SECRET_KEY = os.getenv("SECRET_KEY")
EMAIL_USER = os.getenv("EMAIL_USER")
EMAIL_PASS = os.getenv("EMAIL_PASS")

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

client = MongoClient(MONGO_URL)
db = client["authdb"]
collection = db["users"]

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# ================= UI TEMPLATE =================

def render_template(content, message=None, success=False):
    banner = ""
    if message:
        color = "#28a745" if success else "#dc3545"
        banner = f"""
        <div class="banner" style="background:{color};">
            {message}
        </div>
        """

    return f"""
<!DOCTYPE html>
<html>
<head>
<title>JWT Auth System</title>
<style>
body {{
    margin:0;
    font-family: 'Segoe UI', sans-serif;
    height:100vh;
    display:flex;
    justify-content:center;
    align-items:center;
    background: linear-gradient(135deg, #4e73df, #36b9cc);
}}
.card {{
    background: rgba(255,255,255,0.15);
    backdrop-filter: blur(10px);
    padding:40px;
    width:380px;
    border-radius:15px;
    box-shadow:0 10px 25px rgba(0,0,0,0.3);
    text-align:center;
    color:white;
}}
input {{
    width:100%;
    padding:12px;
    margin:10px 0;
    border-radius:8px;
    border:none;
}}
button {{
    width:100%;
    padding:12px;
    border:none;
    border-radius:8px;
    background:#1cc88a;
    color:white;
    font-weight:bold;
    cursor:pointer;
}}
button:hover {{
    background:#17a673;
}}
a {{
    display:block;
    margin-top:12px;
    color:white;
    text-decoration:none;
    font-size:14px;
}}
.banner {{
    padding:10px;
    border-radius:8px;
    margin-bottom:15px;
}}
.logout {{
    background:#e74a3b;
}}
.logout:hover {{
    background:#c0392b;
}}
</style>
</head>
<body>
<div class="card">
{banner}
{content}
</div>
</body>
</html>
"""

# ================= EMAIL =================

def send_email(to_email, subject, body):
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = EMAIL_USER
    msg["To"] = to_email
    msg.set_content(body)

    with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
        server.login(EMAIL_USER, EMAIL_PASS)
        server.send_message(msg)

# ================= TOKEN =================

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user(token: str = Cookie(None)):
    if not token:
        return None
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email = payload.get("sub")
        return collection.find_one({"email": email})
    except:
        return None

# ================= HOME =================

@app.get("/", response_class=HTMLResponse)
def home():
    return render_template("""
    <h2>Login</h2>
    <form method="post" action="/login">
        <input name="email" type="email" placeholder="Email" required>
        <input name="password" type="password" placeholder="Password" required>
        <button type="submit">Login</button>
    </form>
    <a href="/register">Create Account</a>
    <a href="/forgot-password">Forgot Password?</a>
    """)

# ================= REGISTER =================

@app.get("/register", response_class=HTMLResponse)
def register_page():
    return render_template("""
    <h2>Create Account</h2>
    <form method="post" action="/register">
        <input name="email" type="email" required placeholder="Email">
        <input name="password" type="password" required placeholder="Password">
        <button type="submit">Register</button>
    </form>
    <a href="/">Back</a>
    """)

@app.post("/register", response_class=HTMLResponse)
def register(email: str = Form(...), password: str = Form(...)):

    if collection.find_one({"email": email}):
        return render_template("<h2>Create Account</h2>",
                               message="Email already exists")

    otp = str(random.randint(100000, 999999))

    collection.insert_one({
        "email": email,
        "password": pwd_context.hash(password),
        "is_verified": False,
        "otp": otp,
        "otp_expiry": datetime.utcnow() + timedelta(minutes=5),
        "role": "user"
    })

    send_email(email, "Verify Account", f"Your OTP is {otp}")

    return render_template(f"""
    <h2>Verify Email</h2>
    <form method="post" action="/verify-email">
        <input type="hidden" name="email" value="{email}">
        <input name="otp" placeholder="Enter OTP" required>
        <button type="submit">Verify</button>
    </form>
    """, message="OTP sent to email", success=True)

# ================= VERIFY =================

@app.post("/verify-email", response_class=HTMLResponse)
def verify_email(email: str = Form(...), otp: str = Form(...)):

    user = collection.find_one({"email": email})
    if not user:
        return render_template("<h2>Error</h2>", message="User not found")

    if user["otp"] != otp:
        return render_template("<h2>Verify</h2>",
                               message="Invalid OTP")

    if datetime.utcnow() > user["otp_expiry"]:
        return render_template("<h2>Verify</h2>",
                               message="OTP expired")

    collection.update_one(
        {"email": email},
        {"$set": {"is_verified": True},
         "$unset": {"otp": "", "otp_expiry": ""}}
    )

    return render_template("""
    <h2>Email Verified</h2>
    <a href="/">Login Now</a>
    """, message="Account verified successfully", success=True)

# ================= LOGIN =================

@app.post("/login")
def login(email: str = Form(...), password: str = Form(...)):

    user = collection.find_one({"email": email})

    if not user or not pwd_context.verify(password, user["password"]):
        return render_template("<h2>Login</h2>",
                               message="Invalid credentials")

    if not user["is_verified"]:
        return render_template("<h2>Login</h2>",
                               message="Email not verified")

    token = create_access_token({"sub": email, "role": user["role"]})

    response = RedirectResponse("/dashboard", status_code=302)
    response.set_cookie("token", token, httponly=True)
    return response

# ================= DASHBOARD =================

@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(token: str = Cookie(None)):
    user = get_current_user(token)

    if not user:
        return RedirectResponse("/")

    return render_template(f"""
    <h2>Welcome {user['email']}</h2>
    <p>Role: {user['role']}</p>
    <form method="post" action="/logout">
        <button class="logout" type="submit">Logout</button>
    </form>
    """)

# ================= FORGOT PASSWORD =================

@app.get("/forgot-password", response_class=HTMLResponse)
def forgot_page():
    return render_template("""
    <h2>Forgot Password</h2>
    <form method="post" action="/forgot-password">
        <input name="email" type="email" required placeholder="Email">
        <button type="submit">Send OTP</button>
    </form>
    <a href="/">Back</a>
    """)

@app.post("/forgot-password", response_class=HTMLResponse)
def forgot(email: str = Form(...)):

    user = collection.find_one({"email": email})
    if not user:
        return render_template("<h2>Error</h2>",
                               message="User not found")

    otp = str(random.randint(100000, 999999))

    collection.update_one(
        {"email": email},
        {"$set": {"otp": otp,
                  "otp_expiry": datetime.utcnow() + timedelta(minutes=5)}}
    )

    send_email(email, "Reset Password OTP", f"Your OTP is {otp}")

    return render_template(f"""
    <h2>Reset Password</h2>
    <form method="post" action="/reset-password">
        <input type="hidden" name="email" value="{email}">
        <input name="otp" placeholder="Enter OTP" required>
        <input name="new_password" type="password" placeholder="New Password" required>
        <button type="submit">Reset Password</button>
    </form>
    """, message="OTP sent to email", success=True)

# ================= RESET =================

@app.post("/reset-password", response_class=HTMLResponse)
def reset_password(email: str = Form(...),
                   otp: str = Form(...),
                   new_password: str = Form(...)):

    user = collection.find_one({"email": email})

    if not user or user["otp"] != otp:
        return render_template("<h2>Error</h2>",
                               message="Invalid OTP")

    if datetime.utcnow() > user["otp_expiry"]:
        return render_template("<h2>Error</h2>",
                               message="OTP expired")

    collection.update_one(
        {"email": email},
        {"$set": {"password": pwd_context.hash(new_password)},
         "$unset": {"otp": "", "otp_expiry": ""}}
    )

    return render_template("""
    <h2>Password Reset Successful</h2>
    <a href="/">Login Now</a>
    """, message="Password updated successfully", success=True)

# ================= LOGOUT =================

@app.post("/logout")
def logout():
    response = RedirectResponse("/", status_code=302)
    response.delete_cookie("token")
    return response