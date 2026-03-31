"""
Pydantic schemas for Auth Service
"""
from datetime import datetime
from typing import Optional, Union
from pydantic import BaseModel, EmailStr, Field, UUID4, field_validator
from shared.models.enums import UserRole


# User Schemas
class UserBase(BaseModel):
    """Base user schema"""
    username: str = Field(..., min_length=3, max_length=50)
    email: EmailStr
    full_name: Optional[str] = None
    phone: Optional[str] = None


class UserCreate(UserBase):
    """Schema for user creation"""
    password: str = Field(..., min_length=8, max_length=100)
    role: UserRole
    restaurant_id: Optional[UUID4] = None

    @field_validator('role', mode='before')
    @classmethod
    def normalize_role(cls, v: Union[str, UserRole]) -> UserRole:
        """Convert role string to proper enum value (case-insensitive)"""
        if isinstance(v, UserRole):
            return v
        if isinstance(v, str):
            # Convert to lowercase with underscores
            normalized = v.lower().replace('-', '_')
            try:
                return UserRole(normalized)
            except ValueError:
                # If direct match fails, try to match by name
                for role in UserRole:
                    if role.name.lower() == v.upper().replace('-', '_'):
                        return role
                raise ValueError(f"Invalid role: {v}")
        raise ValueError(f"Role must be a string or UserRole, got {type(v)}")


class StaffCreate(UserBase):
    """Schema for staff creation (chef/customer) by restaurant admin"""
    password: str = Field(..., min_length=8, max_length=100)
    restaurant_id: UUID4
    pos_passcode: Optional[str] = Field(None, min_length=4, max_length=4, pattern=r'^\d{4}$')


class UserUpdate(BaseModel):
    """Schema for user update"""
    full_name: Optional[str] = None
    phone: Optional[str] = None
    email: Optional[EmailStr] = None
    password: Optional[str] = Field(None, min_length=8, max_length=100)
    role: Optional[UserRole] = None
    restaurant_id: Optional[UUID4] = None
    is_active: Optional[bool] = None
    pos_passcode: Optional[str] = Field(None, min_length=4, max_length=4, pattern=r'^\d{4}$')

    @field_validator('role', mode='before')
    @classmethod
    def normalize_role(cls, v: Union[str, UserRole, None]) -> Optional[UserRole]:
        """Convert role string to proper enum value (case-insensitive)"""
        if v is None or isinstance(v, UserRole):
            return v
        if isinstance(v, str):
            # Convert to lowercase with underscores
            normalized = v.lower().replace('-', '_')
            try:
                return UserRole(normalized)
            except ValueError:
                # If direct match fails, try to match by name
                for role in UserRole:
                    if role.name.lower() == v.upper().replace('-', '_'):
                        return role
                raise ValueError(f"Invalid role: {v}")
        raise ValueError(f"Role must be a string or UserRole, got {type(v)}")


class StaffUpdate(BaseModel):
    """Schema for staff update by admin (includes password)"""
    full_name: Optional[str] = None
    phone: Optional[str] = None
    email: Optional[EmailStr] = None
    password: Optional[str] = Field(None, min_length=8, max_length=100)
    is_active: Optional[bool] = None
    pos_passcode: Optional[str] = Field(None, min_length=4, max_length=4, pattern=r'^\d{4}$')


class UserResponse(UserBase):
    """Schema for user response"""
    id: UUID4
    role: UserRole
    restaurant_id: Optional[UUID4] = None
    is_active: bool
    is_verified: bool
    created_at: datetime
    last_login: Optional[datetime] = None

    model_config = {"from_attributes": True, "use_enum_values": False}


# Authentication Schemas
class LoginRequest(BaseModel):
    """Schema for login request"""
    username: str
    password: str
    restaurant_id: Optional[UUID4] = None  # Full UUID for web/API login
    restaurant_code: Optional[str] = None  # 5-digit short code for POS login (first 5 chars of UUID)


class TokenResponse(BaseModel):
    """Schema for token response"""
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int
    user: UserResponse


class TokenRefreshRequest(BaseModel):
    """Schema for token refresh request"""
    refresh_token: str


class TokenRefreshResponse(BaseModel):
    """Schema for token refresh response"""
    access_token: str
    token_type: str = "bearer"
    expires_in: int


# Password Reset Schemas
class PasswordResetRequest(BaseModel):
    """Schema for password reset request"""
    email: EmailStr


class PasswordResetConfirm(BaseModel):
    """Schema for password reset confirmation"""
    token: str
    new_password: str = Field(..., min_length=8, max_length=100)


class PasswordChange(BaseModel):
    """Schema for password change — accepts old_password or current_password"""
    old_password: Optional[str] = None
    current_password: Optional[str] = None  # alias for old_password
    new_password: str = Field(..., min_length=8, max_length=100)

    @property
    def resolved_old_password(self) -> str:
        return self.old_password or self.current_password or ""


class PasswordVerifyRequest(BaseModel):
    """Schema for password verification"""
    password: str


# Response Schemas
class MessageResponse(BaseModel):
    """Generic message response"""
    message: str
    detail: Optional[str] = None


class PasswordVerifyResponse(BaseModel):
    """Schema for password verification response"""
    valid: bool
    message: str


class ErrorResponse(BaseModel):
    """Error response schema"""
    error: str
    detail: Optional[str] = None
    status_code: int


# ─── Partner Schemas ───────────────────────────────────────────────────────────

class PartnerSignup(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    email: EmailStr
    password: str = Field(..., min_length=8, max_length=100)
    full_name: str = Field(..., min_length=1, max_length=255)
    company_name: Optional[str] = None
    phone: Optional[str] = None
    commission_type: str = Field(default="percent", pattern="^(percent|fixed)$")
    commission_value: float = Field(default=10.0, ge=0)


class PartnerLogin(BaseModel):
    username: str
    password: str


class PartnerUpdate(BaseModel):
    full_name: Optional[str] = None
    company_name: Optional[str] = None
    phone: Optional[str] = None
    commission_type: Optional[str] = Field(None, pattern="^(percent|fixed)$")
    commission_value: Optional[float] = Field(None, ge=0)


class PartnerResponse(BaseModel):
    id: UUID4
    username: str
    email: str
    full_name: str
    company_name: Optional[str] = None
    phone: Optional[str] = None
    commission_type: str
    commission_value: float
    is_approved: bool
    is_active: bool
    created_at: datetime
    last_login: Optional[datetime] = None

    model_config = {"from_attributes": True}


class PartnerTokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    partner: PartnerResponse


# ─── POS Passcode Auth Schemas ──────────────────────────────────────────────

class POSStaffMember(BaseModel):
    """Minimal staff info shown on POS login screen (no sensitive data)"""
    id: UUID4
    full_name: str
    role: str

    model_config = {"from_attributes": True}


class POSPasscodeLoginRequest(BaseModel):
    restaurant_id: Optional[UUID4] = None
    restaurant_code: Optional[str] = Field(None, min_length=5, max_length=5)  # 5-char UUID prefix
    passcode: str = Field(..., min_length=4, max_length=4, pattern=r'^\d{4}$')


class POSLoginResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int
    user: UserResponse
