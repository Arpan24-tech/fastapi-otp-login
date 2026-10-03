import os
import random
import time
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

from fastapi import FastAPI, HTTPException, status
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel, EmailStr
from dotenv import load_dotenv

load_dotenv()

app = FastAPI(title="OTP Login System")

# Serve static files from the 'static' directory
app.mount("/static", StaticFiles(directory="static"), name="static")

# Configuration from environment variables
SMTP_SERVER = os.getenv("SMTP_SERVER", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", 587))
SENDER_EMAIL = os.getenv("SENDER_EMAIL")
SENDER_PASSWORD = os.getenv("SENDER_PASSWORD")

# In-memory OTP storage: { "user@example.com": {"otp": "123456", "expires_at": 1700000000} }
otp_store = {}
OTP_EXPIRY_SECONDS = 300  # 5 minutes expiry


class RequestOTPModel(BaseModel):
    email: EmailStr


class VerifyOTPModel(BaseModel):
    email: EmailStr
    otp: str


def send_otp_email(to_email: str, otp: str) -> bool:
    """Sends an HTML-formatted OTP email using standard SMTP."""
    try:
        msg = MIMEMultipart()
        msg['From'] = SENDER_EMAIL
        msg['To'] = to_email
        msg['Subject'] = "Your Login Verification Code"

        body = f"""
        Login Verification
        Your one-time password (OTP) to complete your login is:

        {otp}
        This code will expire in 5 minutes.

        If you did not request this code, you can safely ignore this message.
    """
        msg.attach(MIMEText(body, 'html'))

        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(SENDER_EMAIL, SENDER_PASSWORD)
        server.sendmail(SENDER_EMAIL, to_email, msg.as_string())
        server.quit()
        return True
    except Exception as e:
        print(f"SMTP Error: {e}")
        return False
@app.get("/")
def read_root():
    """Serves the index.html page at the root URL."""
    return FileResponse("static/index.html")

@app.post("/api/send-otp")
def send_otp(data: RequestOTPModel):
    email = data.email.lower().strip()
    # Generate a random 6-digit numerical OTP
    otp = str(random.randint(100000, 999999))
    expires_at = time.time() + OTP_EXPIRY_SECONDS

    # Save/Overwrite OTP record in memory
    otp_store[email] = {
        "otp": otp,
        "expires_at": expires_at
    }

    # Dispatch email
    sent = send_otp_email(email, otp)
    if not sent:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to send OTP email. Please verify SMTP credentials."
        )

    return {"message": "OTP sent successfully to your email."}
@app.post("/api/verify-otp")
def verify_otp(data: VerifyOTPModel):
    email = data.email.lower().strip()
    user_otp = data.otp.strip()

    record = otp_store.get(email)

    if not record:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No active OTP found for this email. Please request a new one."
        )

    # Check for expiration
    if time.time() > record["expires_at"]:
        del otp_store[email]
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="OTP has expired. Please request a new one."
        )

    # Validate OTP code match
    if record["otp"] != user_otp:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid verification code. Please try again."
        )

    # Clear OTP after successful login
    del otp_store[email]

    return {
        "success": True,
        "message": "Successfully authenticated!",
        "email": email
    }