"""
Photo Sorter - Hosted Backend API (MongoDB Version) with Argon2
Handles authentication, licensing, and payment verification
Using Argon2 instead of bcrypt - no byte limitations!

Requirements: pip install argon2-cffi
"""

from fastapi import FastAPI, HTTPException, Depends, BackgroundTasks, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware

import motor.motor_asyncio
from beanie import init_beanie, Document, Indexed, PydanticObjectId
from pydantic import BaseModel, EmailStr, Field, validator
from bson import ObjectId

# CHANGED: Using Argon2 instead of bcrypt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHash

from jose import JWTError, jwt
from datetime import datetime, timedelta
from typing import Optional, List
import secrets
import os
import httpx
import hmac
import hashlib
from dotenv import load_dotenv

load_dotenv()

# ==================== CONFIGURATION ====================
MONGO_DB_URL = os.getenv("MONGO_DB_URL", "mongodb://localhost:27017")
MONGO_DB_NAME = os.getenv("MONGO_DB_NAME", "photosorter_db")
SECRET_KEY = os.getenv("SECRET_KEY", secrets.token_urlsafe(32))
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 30  # 30 days

PAYSTACK_SECRET_KEY = os.getenv("PAYSTACK_SECRET_KEY")
PAYSTACK_PUBLIC_KEY = os.getenv("PAYSTACK_PUBLIC_KEY")
PRICE_PER_STUDENT = 200  # ₦200 per student

# Email configuration
SMTP_HOST = os.getenv("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USERNAME = os.getenv("SMTP_USERNAME")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD")
SMTP_FROM_EMAIL = os.getenv("SMTP_FROM_EMAIL")

# ==================== PASSWORD HASHING WITH ARGON2 ====================

# Initialize Argon2 password hasher
# Argon2 is more secure than bcrypt and has no byte limitations
ph = PasswordHasher(
    time_cost=2,        # Number of iterations
    memory_cost=65536,  # 64 MB memory usage
    parallelism=2,      # Number of parallel threads
    hash_len=32,        # Length of hash in bytes
    salt_len=16         # Length of salt in bytes
)

def hash_password(password: str) -> str:
    """
    Hash password using Argon2
    No byte limitations, very secure
    """
    try:
        return ph.hash(password)
    except Exception as e:
        print(f"Password hashing error: {e}")
        raise HTTPException(status_code=500, detail="Error processing password")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verify password using Argon2
    Returns True if password matches, False otherwise
    """
    try:
        ph.verify(hashed_password, plain_password)
        
        # Check if hash needs rehashing (e.g., if settings changed)
        if ph.check_needs_rehash(hashed_password):
            print("Password hash needs rehashing (outdated parameters)")
        
        return True
    except VerifyMismatchError:
        # Password doesn't match
        return False
    except (VerificationError, InvalidHash) as e:
        # Hash is corrupted or invalid
        print(f"Password verification error: {e}")
        return False
    except Exception as e:
        print(f"Unexpected error during verification: {e}")
        return False


# ==================== DATABASE SETUP ====================
client = motor.motor_asyncio.AsyncIOMotorClient(MONGO_DB_URL)
db = client[MONGO_DB_NAME]

security = HTTPBearer()

# ==================== MODELS ====================
class User(Document):
    name: str
    email: Indexed(EmailStr, unique=True)
    password_hash: str
    phone: Optional[str] = None
    
    # Email verification
    email_verified: bool = False
    verification_token: Optional[str] = None
    
    # Account status
    is_active: bool = True
    created_at: datetime = Field(default_factory=datetime.utcnow)
    last_login: Optional[datetime] = None
    
    # License info
    total_students_purchased: int = 0
    license_valid_until: Optional[datetime] = None
    
    # Device binding
    device_fingerprint: Optional[str] = None

    class Settings:
        name = "users"


class License(Document):
    user_id: PydanticObjectId
    
    # Purchase details
    student_count: int
    amount_paid: float
    payment_reference: Indexed(str, unique=True)
    
    # Status
    payment_status: str = "pending"
    payment_verified_at: Optional[datetime] = None
    
    # Validity
    valid_from: datetime = Field(default_factory=datetime.utcnow)
    valid_until: datetime
    
    # Metadata
    created_at: datetime = Field(default_factory=datetime.utcnow)
    paystack_data: Optional[str] = None

    class Settings:
        name = "licenses"


class OTPVerification(Document):
    email: Indexed(EmailStr)
    otp_code: str
    purpose: str
    
    created_at: datetime = Field(default_factory=datetime.utcnow)
    expires_at: datetime
    verified: bool = False
    attempts: int = 0

    class Settings:
        name = "otp_verifications"


# ==================== PYDANTIC MODELS ====================
class SignupRequest(BaseModel):
    name: str
    email: EmailStr
    password: str
    phone: Optional[str] = None
    
    @validator('password')
    def validate_password(cls, v):
        if len(v) < 6:
            raise ValueError('Password must be at least 6 characters')
        if len(v) > 200:
            raise ValueError('Password too long (max 200 characters)')
        return v


class VerifyEmailRequest(BaseModel):
    email: EmailStr
    otp_code: str


class LoginRequest(BaseModel):
    email: EmailStr
    password: str
    device_fingerprint: str


class ResendOTPRequest(BaseModel):
    email: EmailStr


class LicensePurchaseRequest(BaseModel):
    student_count: int
    email: EmailStr


class TokenResponse(BaseModel):
    access_token: str
    token_type: str
    user: dict
    license_status: dict


# ==================== HELPER FUNCTIONS ====================

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def generate_otp() -> str:
    """Generate 6-digit OTP"""
    return str(secrets.randbelow(1000000)).zfill(6)


async def send_email(to_email: str, subject: str, body: str):
    """Send email using SMTP"""
    try:
        import emails
        from emails.template import JinjaTemplate as T
        
        message = emails.Message(
            subject=subject,
            html=T(body),
            mail_from=(SMTP_FROM_EMAIL, "Photo Sorter App")
        )
        print(message.__str__())
        r = message.send(
            to=to_email,
            smtp={
                "host": SMTP_HOST,
                "port": SMTP_PORT,
                "user": SMTP_USERNAME,
                "password": SMTP_PASSWORD,
                "tls": True
            }
        )
        
        return r.status_code == 250
    except Exception as e:
        print(f"Email error: {e}")
        return False


async def send_otp_email(email: str, otp_code: str, purpose: str):
    """Send OTP verification email"""
    subject_map = {
        "signup": "Verify Your Email - Photo Sorter App",
        "login": "Login Verification Code - Photo Sorter App",
        "reset": "Password Reset Code - Photo Sorter App"
    }
    
    body = f"""
    <html>
        <body style="font-family: Arial, sans-serif; padding: 20px;">
            <h2 style="color: #2C3E50;">Photo Sorter App</h2>
            <p>Your verification code is:</p>
            <h1 style="background: #3498DB; color: white; padding: 20px; text-align: center; border-radius: 8px; letter-spacing: 5px;">
                {otp_code}
            </h1>
            <p style="color: #7F8C8D;">This code will expire in 10 minutes.</p>
            <p style="color: #7F8C8D;">If you didn't request this code, please ignore this email.</p>
        </body>
    </html>
    """
    
    await send_email(email, subject_map.get(purpose, "Verification Code"), body)


async def send_license_email(email: str, license_info: dict):
    """Send license activation email"""
    body = f"""
    <html>
        <body style="font-family: Arial, sans-serif; padding: 20px;">
            <h2 style="color: #2ECC71;">✓ Payment Successful!</h2>
            <p>Thank you for your purchase. Your license has been activated.</p>
            
            <div style="background: #F8F9FA; padding: 20px; border-radius: 8px; margin: 20px 0;">
                <h3>License Details:</h3>
                <p><strong>Students Purchased:</strong> {license_info['student_count']}</p>
                <p><strong>Amount Paid:</strong> ₦{license_info['amount_paid']}</p>
                <p><strong>Valid Until:</strong> {license_info['valid_until']}</p>
                <p><strong>Reference:</strong> {license_info['reference']}</p>
            </div>
            
            <h3 style="color: #3498DB;">Next Steps:</h3>
            <ol>
                <li>Open your Photo Sorter desktop app</li>
                <li>Go to the License page</li>
                <li>Click "Update License from Server"</li>
                <li>Your license will be activated automatically</li>
            </ol>
            
            <p style="color: #7F8C8D; font-size: 12px; margin-top: 30px;">
                If you encounter any issues, please contact support with your reference number.
            </p>
        </body>
    </html>
    """
    
    await send_email(email, "License Activated - Photo Sorter App", body)


def verify_jwt_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Verify JWT token from Authorization header"""
    try:
        token = credentials.credentials
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        return payload
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")


async def get_current_user(token_data: dict = Depends(verify_jwt_token)) -> User:
    """Get current user from JWT token"""
    user = await User.find_one(User.email == token_data["sub"])
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if not user.is_active:
        raise HTTPException(status_code=403, detail="Account deactivated")
    return user


def get_license_status(user: User) -> dict:
    """Get user's license status"""
    now = datetime.utcnow()
    
    if not user.license_valid_until:
        return {
            "valid": False,
            "message": "No active license",
            "students_available": 0,
            "expires": None
        }
    
    is_valid = user.license_valid_until > now
    days_remaining = (user.license_valid_until - now).days if is_valid else 0
    
    return {
        "valid": is_valid,
        "message": "Active" if is_valid else "Expired",
        "students_available": user.total_students_purchased if is_valid else 0,
        "expires": user.license_valid_until.isoformat(),
        "days_remaining": days_remaining
    }


def verify_paystack_signature(payload: bytes, signature: str) -> bool:
    """Verify Paystack webhook signature"""
    if not PAYSTACK_SECRET_KEY:
        return False
    computed_signature = hmac.new(
        PAYSTACK_SECRET_KEY.encode(),
        payload,
        hashlib.sha512
    ).hexdigest()
    return hmac.compare_digest(computed_signature, signature)


# ==================== FASTAPI APP ====================
app = FastAPI(title="Photo Sorter Backend API", version="2.0.0")


@app.on_event("startup")
async def on_startup():
    await init_beanie(
        database=db,
        document_models=[
            User,
            License,
            OTPVerification
        ]
    )
    print("🚀 Beanie initialized")
    print(f"📊 MongoDB: {MONGO_DB_URL}")
    print(f"🗄️  Database: {MONGO_DB_NAME}")
    print(f"🔐 Password Hashing: Argon2 (secure, no byte limits)")


# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ==================== ROUTES ====================

@app.get("/")
async def root():
    return {
        "status": "online",
        "service": "Photo Sorter Backend API",
        "version": "2.0.0 (Argon2)",
        "password_hashing": "Argon2"
    }


@app.post("/auth/signup")
async def signup(request: SignupRequest, background_tasks: BackgroundTasks):
    """Register new user and send OTP"""
    # Check if email exists
    existing_user = await User.find_one(User.email == request.email)
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    # Generate OTP
    otp_code = generate_otp()
    print(otp_code)
    expires_at = datetime.utcnow() + timedelta(minutes=10)
    
    # Create user (unverified) with Argon2 hashing
    password_hash = hash_password(request.password)
    
    user = User(
        name=request.name,
        email=request.email,
        password_hash=password_hash,
        phone=request.phone,
        email_verified=False,
        verification_token=secrets.token_urlsafe(32)
    )
    await user.insert()
    
    # Save OTP
    otp = OTPVerification(
        email=request.email,
        otp_code=otp_code,
        purpose="signup",
        expires_at=expires_at
    )
    await otp.insert()
    
    # Send OTP email
    background_tasks.add_task(send_otp_email, request.email, otp_code, "signup")
    
    return {
        "success": True,
        "message": "OTP sent to your email. Please verify to complete registration.",
        "email": request.email
    }


@app.post("/auth/verify-email")
async def verify_email(request: VerifyEmailRequest):
    """Verify email with OTP"""
    otp = await OTPVerification.find(
        OTPVerification.email == request.email,
        OTPVerification.purpose == "signup",
        OTPVerification.verified == False
    ).sort([("created_at", -1)]).first_or_none()
    
    if not otp:
        raise HTTPException(status_code=404, detail="No verification pending")
    
    if datetime.utcnow() > otp.expires_at:
        raise HTTPException(status_code=400, detail="OTP expired. Request a new one.")
    
    if otp.attempts >= 5:
        raise HTTPException(status_code=400, detail="Too many failed attempts. Request a new OTP.")
    
    if otp.otp_code != request.otp_code:
        otp.attempts += 1
        await otp.save()
        raise HTTPException(status_code=400, detail=f"Invalid OTP. {5 - otp.attempts} attempts remaining.")
    
    otp.verified = True
    
    user = await User.find_one(User.email == request.email)
    if user:
        user.email_verified = True
        await user.save()
    
    await otp.save()
    
    return {
        "success": True,
        "message": "Email verified successfully! You can now login."
    }


@app.post("/auth/login", response_model=TokenResponse)
async def login(request: LoginRequest):
    """Login and get JWT token"""
    user = await User.find_one(User.email == request.email)
    
    if not user:
        raise HTTPException(status_code=401, detail="Invalid email or password")
    
    # Verify password with Argon2
    if not verify_password(request.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    
    if not user.email_verified:
        raise HTTPException(status_code=403, detail="Email not verified. Please verify your email first.")
    
    if not user.is_active:
        raise HTTPException(status_code=403, detail="Account deactivated")
    
    user.last_login = datetime.utcnow()
    user.device_fingerprint = request.device_fingerprint
    await user.save()
    
    access_token = create_access_token(data={"sub": user.email, "user_id": str(user.id)})
    
    license_status = get_license_status(user)
    
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user": {
            "id": str(user.id),
            "name": user.name,
            "email": user.email,
            "phone": user.phone,
            "email_verified": user.email_verified
        },
        "license_status": license_status
    }


@app.post("/auth/resend-otp")
async def resend_otp(request: ResendOTPRequest, background_tasks: BackgroundTasks):
    """Resend OTP"""
    user = await User.find_one(User.email == request.email)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    if user.email_verified:
        raise HTTPException(status_code=400, detail="Email already verified")
    
    otp_code = generate_otp()
    expires_at = datetime.utcnow() + timedelta(minutes=10)
    
    otp = OTPVerification(
        email=request.email,
        otp_code=otp_code,
        purpose="signup",
        expires_at=expires_at
    )
    await otp.insert()
    
    background_tasks.add_task(send_otp_email, request.email, otp_code, "signup")
    
    return {"success": True, "message": "OTP sent to your email"}


@app.get("/license/status")
async def get_license(current_user: User = Depends(get_current_user)):
    """Get user's license status"""
    license_status = get_license_status(current_user)
    return license_status


@app.post("/license/purchase/initialize")
async def initialize_license_purchase(
    request: LicensePurchaseRequest,
    current_user: User = Depends(get_current_user)
):
    """Initialize license purchase with Paystack"""
    if request.student_count < 1:
        raise HTTPException(status_code=400, detail="Minimum 1 student required")
    
    amount = request.student_count * PRICE_PER_STUDENT * 100
    reference = f"PHOTO_{current_user.id}_{secrets.token_hex(8).upper()}"
    
    async with httpx.AsyncClient() as client:
        response = await client.post(
            "https://api.paystack.co/transaction/initialize",
            headers={
                "Authorization": f"Bearer {PAYSTACK_SECRET_KEY}",
                "Content-Type": "application/json"
            },
            json={
                "email": request.email,
                "amount": amount,
                "reference": reference,
                "currency": "NGN",
                "callback_url": f"https://yourapp.com/payment-success",
                "metadata": {
                    "user_id": str(current_user.id),
                    "student_count": request.student_count,
                    "product": "photo_sorter_license"
                }
            }
        )
    
    if response.status_code != 200:
        print(response.json())
        raise HTTPException(status_code=response.status_code, detail="Payment initialization failed")
    
    data = response.json()
    
    if not data.get("status"):
        raise HTTPException(status_code=400, detail="Payment initialization failed")
    
    license_record = License(
        user_id=current_user.id,
        student_count=request.student_count,
        amount_paid=request.student_count * PRICE_PER_STUDENT,
        payment_reference=reference,
        payment_status="pending",
        valid_until=datetime.utcnow() + timedelta(days=30)
    )
    await license_record.insert()
    
    return {
        "success": True,
        "payment_url": data["data"]["authorization_url"],
        "reference": reference,
        "amount": request.student_count * PRICE_PER_STUDENT,
        "public_key": PAYSTACK_PUBLIC_KEY
    }


@app.post("/webhook/paystack")
async def paystack_webhook(request: Request, background_tasks: BackgroundTasks):
    """Handle Paystack webhook"""
    signature = request.headers.get("x-paystack-signature")
    body = await request.body()
    
    if not signature or not verify_paystack_signature(body, signature):
        raise HTTPException(status_code=401, detail="Invalid signature")
    
    import json
    event = json.loads(body)
    
    if event.get("event") == "charge.success":
        data = event.get("data", {})
        reference = data.get("reference")
        status = data.get("status")
        
        if status == "success":
            license_record = await License.find_one(
                License.payment_reference == reference
            )
            
            if license_record and license_record.payment_status == "pending":
                license_record.payment_status = "completed"
                license_record.payment_verified_at = datetime.utcnow()
                license_record.paystack_data = json.dumps(data)
                
                user = await User.find_one(User.id == license_record.user_id)
                if user:
                    user.total_students_purchased += license_record.student_count
                    user.license_valid_until = license_record.valid_until
                    await user.save()
                
                await license_record.save()
                
                if user:
                    background_tasks.add_task(
                        send_license_email,
                        user.email,
                        {
                            "student_count": license_record.student_count,
                            "amount_paid": license_record.amount_paid,
                            "valid_until": license_record.valid_until.strftime("%Y-%m-%d"),
                            "reference": reference
                        }
                    )
    
    return {"status": "received"}


@app.post("/license/verify/{reference}")
async def verify_license_payment(
    reference: str,
    current_user: User = Depends(get_current_user)
):
    """Verify payment and activate license"""
    license_record = await License.find_one(
        License.payment_reference == reference,
        License.user_id == current_user.id
    )
    
    if not license_record:
        raise HTTPException(status_code=404, detail="License not found")
    
    if license_record.payment_status == "completed":
        return {
            "success": True,
            "message": "License already activated",
            "license": get_license_status(current_user)
        }
    
    async with httpx.AsyncClient() as client:
        response = await client.get(
            f"https://api.paystack.co/transaction/verify/{reference}",
            headers={"Authorization": f"Bearer {PAYSTACK_SECRET_KEY}"}
        )
    
    if response.status_code != 200:
        raise HTTPException(status_code=500, detail="Verification failed")
    
    data = response.json()
    
    if data.get("data", {}).get("status") == "success":
        license_record.payment_status = "completed"
        license_record.payment_verified_at = datetime.utcnow()
        
        current_user.total_students_purchased += license_record.student_count
        current_user.license_valid_until = license_record.valid_until
        
        await license_record.save()
        await current_user.save()
        
        return {
            "success": True,
            "message": "License activated successfully",
            "license": get_license_status(current_user)
        }
    
    return {
        "success": False,
        "message": "Payment not yet confirmed",
        "status": data.get("data", {}).get("status")
    }


@app.get("/license/check")
async def check_license_from_device(
    device_fingerprint: str,
    current_user: User = Depends(get_current_user)
):
    """Check license status from desktop app"""
    if current_user.device_fingerprint != device_fingerprint:
        raise HTTPException(status_code=403, detail="Device not authorized")
    
    return get_license_status(current_user)


# ==================== RUN SERVER ====================
if __name__ == "__main__":
    import uvicorn
    
    print("\n🚀 Starting Photo Sorter Backend API (Argon2 Version)...")
    print(f"📍 API: http://localhost:8001")
    print(f"📄 Docs: http://localhost:8001/docs")
    print(f"🔐 Password Hashing: Argon2 (Winner of Password Hashing Competition)")
    print(f"\n⚠️  Configure:")
    print(f"   1. MONGO_DB_URL in .env")
    print(f"   2. PAYSTACK_SECRET_KEY in .env")
    print(f"   3. SMTP settings in .env")
    print(f"\n💡 First time? Install: pip install argon2-cffi\n")

    uvicorn.run(app, host="127.0.0.1", port=8001)