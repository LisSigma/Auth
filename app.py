
from fastapi import FastAPI, HTTPException, Depends, Header, Request
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import create_engine, Column, Integer, String, Boolean, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from datetime import datetime, timedelta
import jwt
import uuid
import hashlib
from pydantic import BaseModel
from typing import Optional
import uvicorn
import aiosqlite

# Database setup
SQLALCHEMY_DATABASE_URL = "sqlite:///./auth.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Models
class User(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    license_key = Column(String, unique=True, index=True)
    hwid = Column(String, nullable=True)
    ip_address = Column(String, nullable=True)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    last_login = Column(DateTime, nullable=True)
    total_logins = Column(Integer, default=0)

# Create tables
Base.metadata.create_all(bind=engine)

# FastAPI app
app = FastAPI(title="Auth API", version="1.0.0")

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Pydantic models
class AuthRequest(BaseModel):
    license_key: str
    hwid: str
    ip_address: str

class AuthResponse(BaseModel):
    status: bool
    message: str
    token: Optional[str] = None
    license_key: str

class ValidateRequest(BaseModel):
    token: str

class RegisterRequest(BaseModel):
    license_key: str

# JWT configuration
SECRET_KEY = "your-secret-key-change-in-production"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

# Dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Helper functions
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def verify_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except jwt.PyJWTError:
        return None

def hash_hwid(hwid: str) -> str:
    return hashlib.sha256(hwid.encode()).hexdigest()

# Routes
@app.post("/api/auth", response_model=AuthResponse)
async def authenticate(request: AuthRequest, db: Session = Depends(get_db)):
    """Authenticate user with license key, HWID, and IP"""
    
    # Find user by license key
    user = db.query(User).filter(User.license_key == request.license_key).first()
    
    if not user:
        raise HTTPException(status_code=401, detail="Invalid license key")
    
    if not user.is_active:
        raise HTTPException(status_code=403, detail="License is deactivated")
    
    # If it's first login, register HWID and IP
    if not user.hwid:
        user.hwid = hash_hwid(request.hwid)
        user.ip_address = request.ip_address
        user.last_login = datetime.utcnow()
        user.total_logins = 1
        db.commit()
        
        # Create token
        token_data = {
            "sub": request.license_key,
            "hwid": user.hwid,
            "ip": request.ip_address
        }
        token = create_access_token(token_data)
        
        return AuthResponse(
            status=True,
            message="HWID registered successfully",
            token=token,
            license_key=request.license_key
        )
    
    # Check if HWID matches
    hashed_hwid = hash_hwid(request.hwid)
    if user.hwid != hashed_hwid:
        raise HTTPException(status_code=403, detail="HWID mismatch")
    
    # Check if IP matches (optional, can be made strict)
    if user.ip_address and user.ip_address != request.ip_address:
        raise HTTPException(status_code=403, detail="IP address mismatch")
    
    # Update login info
    user.last_login = datetime.utcnow()
    user.total_logins += 1
    db.commit()
    
    # Create token
    token_data = {
        "sub": request.license_key,
        "hwid": user.hwid,
        "ip": request.ip_address
    }
    token = create_access_token(token_data)
    
    return AuthResponse(
        status=True,
        message="Authentication successful",
        token=token,
        license_key=request.license_key
    )

@app.post("/api/validate", response_model=dict)
async def validate_token(request: ValidateRequest):
    """Validate JWT token"""
    payload = verify_token(request.token)
    
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    
    return {
        "status": True,
        "message": "Token is valid",
        "license_key": payload.get("sub"),
        "hwid": payload.get("hwid")
    }

@app.post("/api/register", response_model=dict)
async def register_license(request: RegisterRequest, db: Session = Depends(get_db)):
    """Register a new license key (admin function)"""
    
    # Check if key already exists
    existing = db.query(User).filter(User.license_key == request.license_key).first()
    if existing:
        raise HTTPException(status_code=400, detail="License key already exists")
    
    # Create new user
    new_user = User(
        license_key=request.license_key,
        is_active=True,
        created_at=datetime.utcnow()
    )
    
    db.add(new_user)
    db.commit()
    
    return {
        "status": True,
        "message": "License key registered successfully",
        "license_key": request.license_key
    }

@app.get("/api/check/{license_key}", response_model=dict)
async def check_license(license_key: str, db: Session = Depends(get_db)):
    """Check license status"""
    user = db.query(User).filter(User.license_key == license_key).first()
    
    if not user:
        raise HTTPException(status_code=404, detail="License key not found")
    
    return {
        "status": True,
        "license_key": user.license_key,
        "is_active": user.is_active,
        "has_hwid": user.hwid is not None,
        "created_at": user.created_at.isoformat() if user.created_at else None,
        "last_login": user.last_login.isoformat() if user.last_login else None,
        "total_logins": user.total_logins
    }

@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "status": "online",
        "service": "Auth API",
        "version": "1.0.0",
        "endpoints": [
            "/api/auth - POST - Authenticate",
            "/api/validate - POST - Validate token",
            "/api/register - POST - Register license",
            "/api/check/{key} - GET - Check license",
            "/docs - API Documentation"
        ]
    }

# For Flask compatibility (if needed)
if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=5000)
