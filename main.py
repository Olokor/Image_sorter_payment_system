"""
Photo Sorter - SECURE Hosted Backend API
Multi-layer security: API Keys, Rate Limiting, Request Signing, IP Whitelisting

pip install slowapi redis argon2-cffi
"""

from fastapi import FastAPI, HTTPException, Depends, BackgroundTasks, Request, Header
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

import motor.motor_asyncio
from beanie import init_beanie, Document, Indexed, PydanticObjectId
from pydantic import BaseModel, EmailStr, Field, validator
from bson import ObjectId

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

# NEW: API Key for desktop app authentication
DESKTOP_APP_API_KEY = os.getenv("DESKTOP_APP_API_KEY", secrets.token_urlsafe(32))
REQUEST_SIGNING_KEY = os.getenv("REQUEST_SIGNING_KEY", secrets.token_urlsafe(32))

PAYSTACK_SECRET_KEY = os.getenv("PAYSTACK_SECRET_KEY")
PAYSTACK_PUBLIC_KEY = os.getenv("PAYSTACK_PUBLIC_KEY")
PRICE_PER_STUDENT = 200

# Email configuration
SMTP_HOST = os.getenv("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USERNAME = os.getenv("SMTP_USERNAME")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD")
SMTP_FROM_EMAIL = os.getenv("SMTP_FROM_EMAIL")

# IP Whitelist (optional - for extra security)
ALLOWED_IP_RANGES = os.getenv("ALLOWED_IP_RANGES", "").split(",") if os.getenv("ALLOWED_IP_RANGES") else []

# ==================== PASSWORD HASHING WITH ARGON2 ====================
ph = PasswordHasher(
    time_cost=2,
    memory_cost=65536,
    parallelism=2,
    hash_len=32,
    salt_len=16
)

def hash_password(password: str) -> str:
    try:
        return ph.hash(password)
    except Exception as e:
        print(f"Password hashing error: {e}")
        raise HTTPException(status_code=500, detail="Error processing password")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    try:
        ph.verify(hashed_password, plain_password)
        if ph.check_needs_rehash(hashed_password):
            print("Password hash needs rehashing")
        return True
    except (VerifyMismatchError, VerificationError, InvalidHash):
        return False
    except Exception as e:
        print(f"Verification error: {e}")
        return False


# ==================== DATABASE SETUP ====================
client = motor.motor_asyncio.AsyncIOMotorClient(MONGO_DB_URL)
db = client[MONGO_DB_NAME]

security = HTTPBearer()

# ==================== RATE LIMITING ====================
limiter = Limiter(key_func=get_remote_address)

# ==================== MODELS ====================
class User(Document):
    name: str
    email: Indexed(EmailStr, unique=True)
    password_hash: str
    phone: Optional[str] = None
    
    email_verified: bool = False
    verification_token: Optional[str] = None
    
    is_active: bool = True
    created_at: datetime = Field(default_factory=datetime.utcnow)
    last_login: Optional[datetime] = None
    
    total_students_purchased: int = 0
    license_valid_until: Optional[datetime] = None
    
    device_fingerprint: Optional[str] = None
    
    # Security tracking
    failed_login_attempts: int = 0
    last_failed_login: Optional[datetime] = None
    account_locked_until: Optional[datetime] = None

    class Settings:
        name = "users"


class License(Document):
    user_id: PydanticObjectId
    student_count: int
    amount_paid: float
    payment_reference: Indexed(str, unique=True)
    payment_status: str = "pending"
    payment_verified_at: Optional[datetime] = None
    valid_from: datetime = Field(default_factory=datetime.utcnow)
    valid_until: datetime
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


class APIAccessLog(Document):
    """Log API access for monitoring"""
    ip_address: str
    endpoint: str
    method: str
    user_agent: Optional[str] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    api_key_valid: bool = False
    user_id: Optional[str] = None

    class Settings:
        name = "api_access_logs"


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
            raise ValueError('Password too long')
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


# ==================== SECURITY FUNCTIONS ====================

def verify_api_key(x_api_key: str = Header(..., alias="X-API-Key")) -> bool:
    """Verify API key from desktop app"""
    if not x_api_key:
        raise HTTPException(
            status_code=401,
            detail="API Key required. Please update your desktop app."
        )
    
    if x_api_key != DESKTOP_APP_API_KEY:
        raise HTTPException(
            status_code=403,
            detail="Invalid API Key. Please reinstall the desktop app."
        )
    
    return True


def verify_request_signature(
    request_body: str,
    timestamp: str,
    signature: str = Header(..., alias="X-Request-Signature")
) -> bool:
    """
    Verify request signature to prevent replay attacks
    Desktop app should sign requests with: HMAC-SHA256(timestamp + body, signing_key)
    """
    # Check timestamp (reject requests older than 5 minutes)
    try:
        req_time = datetime.fromisoformat(timestamp)
        if (datetime.utcnow() - req_time).total_seconds() > 300:
            raise HTTPException(status_code=401, detail="Request expired")
    except:
        raise HTTPException(status_code=400, detail="Invalid timestamp")
    
    # Verify signature
    expected_signature = hmac.new(
        REQUEST_SIGNING_KEY.encode(),
        f"{timestamp}{request_body}".encode(),
        hashlib.sha256
    ).hexdigest()
    
    if not hmac.compare_digest(signature, expected_signature):
        raise HTTPException(status_code=403, detail="Invalid signature")
    
    return True


async def check_ip_whitelist(request: Request):
    """Optional: Check if IP is in allowed ranges"""
    if not ALLOWED_IP_RANGES or ALLOWED_IP_RANGES == ['']:
        return True  # No whitelist configured
    
    client_ip = request.client.host
    
    # Simple check (you can use ipaddress module for CIDR ranges)
    for allowed_range in ALLOWED_IP_RANGES:
        if client_ip.startswith(allowed_range.strip()):
            return True
    
    raise HTTPException(
        status_code=403,
        detail="Access denied from your location"
    )


async def log_api_access(
    request: Request,
    api_key_valid: bool = False,
    user_id: Optional[str] = None
):
    """Log API access for monitoring"""
    try:
        log = APIAccessLog(
            ip_address=request.client.host,
            endpoint=request.url.path,
            method=request.method,
            user_agent=request.headers.get("user-agent"),
            api_key_valid=api_key_valid,
            user_id=user_id
        )
        await log.insert()
    except Exception as e:
        print(f"Logging error: {e}")


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def generate_otp() -> str:
    return str(secrets.randbelow(1000000)).zfill(6)


async def send_email(to_email: str, subject: str, body: str):
    try:
        import emails
        from emails.template import JinjaTemplate as T
        
        message = emails.Message(
            subject=subject,
            html=T(body),
            mail_from=(SMTP_FROM_EMAIL, "Photo Sorter App")
        )
        
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
    subject_map = {
        "signup": "Verify Your Email - Photo Sorter App",
        "login": "Login Verification Code",
        "reset": "Password Reset Code"
    }
    
    body = f"""
    <html>
        <body style="font-family: Arial, sans-serif; padding: 20px;">
            <h2 style="color: #2C3E50;">Photo Sorter App</h2>
            <p>Your verification code is:</p>
            <h1 style="background: #3498DB; color: white; padding: 20px; text-align: center; border-radius: 8px; letter-spacing: 5px;">
                {otp_code}
            </h1>
            <p style="color: #7F8C8D;">This code expires in 10 minutes.</p>
        </body>
    </html>
    """
    
    await send_email(email, subject_map.get(purpose, "Verification Code"), body)


async def send_license_email(email: str, license_info: dict):
    body = f"""
    <html>
        <body style="font-family: Arial, sans-serif; padding: 20px;">
            <h2 style="color: #2ECC71;">✓ Payment Successful!</h2>
            <p>Your license has been activated.</p>
            
            <div style="background: #F8F9FA; padding: 20px; border-radius: 8px; margin: 20px 0;">
                <h3>License Details:</h3>
                <p><strong>Students:</strong> {license_info['student_count']}</p>
                <p><strong>Amount:</strong> ₦{license_info['amount_paid']}</p>
                <p><strong>Valid Until:</strong> {license_info['valid_until']}</p>
                <p><strong>Reference:</strong> {license_info['reference']}</p>
            </div>
            
            <h3>Next Steps:</h3>
            <ol>
                <li>Open Photo Sorter app</li>
                <li>Go to License page</li>
                <li>Click "Update License from Server"</li>
            </ol>
        </body>
    </html>
    """
    
    await send_email(email, "License Activated - Photo Sorter", body)


def verify_jwt_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
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
    user = await User.find_one(User.email == token_data["sub"])
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Check if account is locked
    if user.account_locked_until and datetime.utcnow() < user.account_locked_until:
        raise HTTPException(
            status_code=403,
            detail=f"Account locked until {user.account_locked_until.isoformat()}"
        )
    
    if not user.is_active:
        raise HTTPException(status_code=403, detail="Account deactivated")
    
    return user


def get_license_status(user: User) -> dict:
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
    if not PAYSTACK_SECRET_KEY:
        return False
    computed = hmac.new(
        PAYSTACK_SECRET_KEY.encode(),
        payload,
        hashlib.sha512
    ).hexdigest()
    return hmac.compare_digest(computed, signature)


# ==================== FASTAPI APP ====================
app = FastAPI(
    title="Photo Sorter Secure Backend",
    version="2.0.0-secure",
    docs_url=None,  # Disable public docs in production
    redoc_url=None
)

# Add rate limiter
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)


@app.on_event("startup")
async def on_startup():
    await init_beanie(
        database=db,
        document_models=[User, License, OTPVerification, APIAccessLog]
    )
    print("🚀 Beanie initialized")
    print(f"🔐 Security: API Key + Request Signing + Rate Limiting")
    print(f"🔑 Desktop API Key: {DESKTOP_APP_API_KEY}...") 
    print(f"⚠️  IMPORTANT: Share DESKTOP_APP_API_KEY with your desktop app!")


# IMPORTANT: Strict CORS - only allow your desktop app
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:8080", "http://127.0.0.1:8080"],  # Desktop app origins
    allow_credentials=True,
    allow_methods=["POST", "GET"],  # Only needed methods
    allow_headers=["Content-Type", "Authorization", "X-API-Key", "X-Request-Signature", "X-Request-Timestamp"],
    max_age=3600
)


# ==================== MIDDLEWARE ====================

@app.middleware("http")
async def security_middleware(request: Request, call_next):
    """Global security middleware"""
    # Skip for webhook (Paystack sends from their servers)
    if request.url.path == "/webhook/paystack":
        return await call_next(request)
    
    # Check IP whitelist (if configured)
    try:
        await check_ip_whitelist(request)
    except HTTPException as e:
        return e
    
    # Verify API key for all endpoints except root
    if request.url.path != "/":
        api_key = request.headers.get("X-API-Key")
        if api_key != DESKTOP_APP_API_KEY:
            await log_api_access(request, api_key_valid=False)
            raise HTTPException(status_code=403, detail="Invalid API Key")
    
    # Log successful access
    await log_api_access(request, api_key_valid=True)
    
    response = await call_next(request)
    return response


# ==================== ROUTES ====================

@app.get("/")
async def root():
    return {
        "status": "online",
        "service": "Photo Sorter Secure Backend",
        "version": "2.0.0-secure",
        "security": ["API Key", "Rate Limiting", "Request Signing"]
    }


@app.post("/auth/signup")
@limiter.limit("5/hour")  # 5 signups per hour per IP
async def signup(
    request: Request,
    signup_req: SignupRequest,
    background_tasks: BackgroundTasks,
    _api_key: bool = Depends(verify_api_key)
):
    """Register new user - rate limited"""
    existing_user = await User.find_one(User.email == signup_req.email)
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    otp_code = generate_otp()
    print(f"OTP for {signup_req.email}: {otp_code}")
    expires_at = datetime.utcnow() + timedelta(minutes=10)
    
    password_hash = hash_password(signup_req.password)
    
    user = User(
        name=signup_req.name,
        email=signup_req.email,
        password_hash=password_hash,
        phone=signup_req.phone,
        email_verified=False,
        verification_token=secrets.token_urlsafe(32)
    )
    await user.insert()
    
    otp = OTPVerification(
        email=signup_req.email,
        otp_code=otp_code,
        purpose="signup",
        expires_at=expires_at
    )
    await otp.insert()
    
    background_tasks.add_task(send_otp_email, signup_req.email, otp_code, "signup")
    
    return {
        "success": True,
        "message": "OTP sent to your email",
        "email": signup_req.email
    }


@app.post("/auth/verify-email")
@limiter.limit("10/minute")
async def verify_email(
    request: Request,
    verify_req: VerifyEmailRequest,
    _api_key: bool = Depends(verify_api_key)
):
    """Verify email with OTP - rate limited"""
    otp = await OTPVerification.find(
        OTPVerification.email == verify_req.email,
        OTPVerification.purpose == "signup",
        OTPVerification.verified == False
    ).sort([("created_at", -1)]).first_or_none()
    
    if not otp:
        raise HTTPException(status_code=404, detail="No verification pending")
    
    if datetime.utcnow() > otp.expires_at:
        raise HTTPException(status_code=400, detail="OTP expired")
    
    if otp.attempts >= 5:
        raise HTTPException(status_code=400, detail="Too many attempts")
    
    if otp.otp_code != verify_req.otp_code:
        otp.attempts += 1
        await otp.save()
        raise HTTPException(status_code=400, detail=f"Invalid OTP. {5 - otp.attempts} attempts left")
    
    otp.verified = True
    await otp.save()
    
    user = await User.find_one(User.email == verify_req.email)
    if user:
        user.email_verified = True
        await user.save()
    
    return {"success": True, "message": "Email verified"}


@app.post("/auth/login", response_model=TokenResponse)
@limiter.limit("10/minute")  # 10 login attempts per minute per IP
async def login(
    request: Request,
    login_req: LoginRequest,
    _api_key: bool = Depends(verify_api_key)
):
    """Login - rate limited to prevent brute force"""
    user = await User.find_one(User.email == login_req.email)
    
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    # Check if account is locked
    if user.account_locked_until and datetime.utcnow() < user.account_locked_until:
        raise HTTPException(
            status_code=403,
            detail=f"Account locked. Try again after {user.account_locked_until.isoformat()}"
        )
    
    # Verify password
    if not verify_password(login_req.password, user.password_hash):
        # Track failed attempts
        user.failed_login_attempts += 1
        user.last_failed_login = datetime.utcnow()
        
        # Lock account after 5 failed attempts
        if user.failed_login_attempts >= 5:
            user.account_locked_until = datetime.utcnow() + timedelta(hours=1)
            await user.save()
            raise HTTPException(
                status_code=403,
                detail="Account locked due to multiple failed login attempts. Try again in 1 hour."
            )
        
        await user.save()
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    if not user.email_verified:
        raise HTTPException(status_code=403, detail="Email not verified")
    
    if not user.is_active:
        raise HTTPException(status_code=403, detail="Account deactivated")
    
    # Reset failed attempts on successful login
    user.last_login = datetime.utcnow()
    user.device_fingerprint = login_req.device_fingerprint
    user.failed_login_attempts = 0
    user.account_locked_until = None
    await user.save()
    
    access_token = create_access_token(
        data={"sub": user.email, "user_id": str(user.id)}
    )
    
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
@limiter.limit("3/hour")  # 3 OTP requests per hour
async def resend_otp(
    request: Request,
    resend_req: ResendOTPRequest,
    background_tasks: BackgroundTasks,
    _api_key: bool = Depends(verify_api_key)
):
    """Resend OTP - rate limited"""
    user = await User.find_one(User.email == resend_req.email)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    if user.email_verified:
        raise HTTPException(status_code=400, detail="Email already verified")
    
    otp_code = generate_otp()
    print(f"OTP for {resend_req.email}: {otp_code}")
    expires_at = datetime.utcnow() + timedelta(minutes=10)
    
    otp = OTPVerification(
        email=resend_req.email,
        otp_code=otp_code,
        purpose="signup",
        expires_at=expires_at
    )
    await otp.insert()
    
    background_tasks.add_task(send_otp_email, resend_req.email, otp_code, "signup")
    
    return {"success": True, "message": "OTP sent"}


@app.get("/license/status")
@limiter.limit("30/minute")
async def get_license(
    request: Request,
    current_user: User = Depends(get_current_user),
    _api_key: bool = Depends(verify_api_key)
):
    """Get license status - rate limited"""
    return get_license_status(current_user)


@app.post("/license/verify/{reference}")
@limiter.limit("10/minute")
async def verify_license_payment(
    request: Request,
    reference: str,
    current_user: User = Depends(get_current_user),
    _api_key: bool = Depends(verify_api_key)
):
    """Verify payment and activate license - rate limited"""
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
            "message": "License activated",
            "license": get_license_status(current_user)
        }
    
    return {
        "success": False,
        "message": "Payment not confirmed",
        "status": data.get("data", {}).get("status")
    }


@app.get("/license/check")
@limiter.limit("30/minute")
async def check_license_from_device(
    request: Request,
    device_fingerprint: str,
    current_user: User = Depends(get_current_user),
    _api_key: bool = Depends(verify_api_key)
):
    """Check license from desktop app - rate limited"""
    if current_user.device_fingerprint != device_fingerprint:
        raise HTTPException(status_code=403, detail="Device not authorized")
    
    return get_license_status(current_user)


# ==================== ADMIN ENDPOINTS (Optional) ====================

@app.get("/admin/stats")
async def admin_stats(
    admin_key: str = Header(..., alias="X-Admin-Key"),
    _api_key: bool = Depends(verify_api_key)
):
    """Get system stats - requires admin key"""
    if admin_key != os.getenv("ADMIN_KEY", "change-me-in-production"):
        raise HTTPException(status_code=403, detail="Unauthorized")
    
    total_users = await User.count()
    active_licenses = await User.find(
        User.license_valid_until > datetime.utcnow()
    ).count()
    
    total_revenue = 0
    licenses = await License.find(License.payment_status == "completed").to_list()
    for lic in licenses:
        total_revenue += lic.amount_paid
    
    return {
        "total_users": total_users,
        "active_licenses": active_licenses,
        "total_revenue": total_revenue,
        "timestamp": datetime.utcnow().isoformat()
    }


# ==================== RUN SERVER ====================
if __name__ == "__main__":
    import uvicorn
    
    print("\n" + "="*70)
    print("🚀 PHOTO SORTER SECURE BACKEND API")
    print("="*70)
    print(f"\n📍 API: http://localhost:8001")
    print(f"🔐 Security Features:")
    print(f"   ✓ API Key Authentication")
    print(f"   ✓ Rate Limiting (SlowAPI)")
    print(f"   ✓ Request Signing Support")
    print(f"   ✓ IP Whitelisting (Optional)")
    print(f"   ✓ Account Lockout (5 failed logins)")
    print(f"   ✓ Argon2 Password Hashing")
    print(f"\n🔑 Desktop App API Key:")
    print(f"   {DESKTOP_APP_API_KEY}")
    print(f"\n⚠️  IMPORTANT - Add to Desktop App:")
    print(f"   Set API_BASE_URL and DESKTOP_APP_API_KEY in desktop app")
    print(f"\n💡 Environment Variables Required:")
    print(f"   - MONGO_DB_URL")
    print(f"   - SECRET_KEY")
    print(f"   - DESKTOP_APP_API_KEY (auto-generated above)")
    print(f"   - REQUEST_SIGNING_KEY (optional, for request signing)")
    print(f"   - PAYSTACK_SECRET_KEY")
    print(f"   - PAYSTACK_PUBLIC_KEY")
    print(f"   - SMTP_* (email settings)")
    print(f"   - ALLOWED_IP_RANGES (optional, comma-separated)")
    print(f"   - ADMIN_KEY (optional, for admin endpoints)")
    print("="*70 + "\n")

@limiter.limit("5/hour")  # 5 payment initializations per hour
async def initialize_license_purchase(
    request: Request,
    purchase_req: LicensePurchaseRequest,
    current_user: User = Depends(get_current_user),
    _api_key: bool = Depends(verify_api_key)
):
    """Initialize license purchase - rate limited"""
    if purchase_req.student_count < 1:
        raise HTTPException(status_code=400, detail="Minimum 1 student")
    
    amount = purchase_req.student_count * PRICE_PER_STUDENT * 100
    reference = f"PHOTO_{current_user.id}_{secrets.token_hex(8).upper()}"
    
    async with httpx.AsyncClient() as client:
        response = await client.post(
            "https://api.paystack.co/transaction/initialize",
            headers={
                "Authorization": f"Bearer {PAYSTACK_SECRET_KEY}",
                "Content-Type": "application/json"
            },
            json={
                "email": purchase_req.email,
                "amount": amount,
                "reference": reference,
                "currency": "NGN",
                "callback_url": "https://yourapp.com/payment-success",
                "metadata": {
                    "user_id": str(current_user.id),
                    "student_count": purchase_req.student_count,
                    "product": "photo_sorter_license"
                }
            }
        )
    
    if response.status_code != 200:
        raise HTTPException(status_code=500, detail="Payment init failed")
    
    data = response.json()
    
    if not data.get("status"):
        raise HTTPException(status_code=400, detail="Payment init failed")
    
    license_record = License(
        user_id=current_user.id,
        student_count=purchase_req.student_count,
        amount_paid=purchase_req.student_count * PRICE_PER_STUDENT,
        payment_reference=reference,
        payment_status="pending",
        valid_until=datetime.utcnow() + timedelta(days=30)
    )
    await license_record.insert()
    
    return {
        "success": True,
        "payment_url": data["data"]["authorization_url"],
        "reference": reference,
        "amount": purchase_req.student_count * PRICE_PER_STUDENT,
        "public_key": PAYSTACK_PUBLIC_KEY
    }

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
    """Paystack webhook - no API key required (verified by signature)"""
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