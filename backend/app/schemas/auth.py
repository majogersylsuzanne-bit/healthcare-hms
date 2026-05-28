"""Authentication-related Pydantic schemas."""
from pydantic import BaseModel, EmailStr, Field
from typing import List, Optional
from datetime import datetime
from app.core.enums import RoleType, PortalType


class UserBase(BaseModel):
    """Base user schema."""

    email: EmailStr = Field(..., description="User email address")
    first_name: str = Field(..., min_length=1, max_length=100)
    last_name: str = Field(..., min_length=1, max_length=100)
    is_active: bool = Field(default=True)


class UserCreate(UserBase):
    """Schema for user registration/creation."""

    password: str = Field(
        ...,
        min_length=12,
        description="Password must be at least 12 characters with uppercase, lowercase, numbers, and symbols",
    )
    role: RoleType = Field(..., description="User role")
    portal: PortalType = Field(..., description="Portal assignment")


class UserUpdate(BaseModel):
    """Schema for user profile updates."""

    first_name: Optional[str] = Field(None, min_length=1, max_length=100)
    last_name: Optional[str] = Field(None, min_length=1, max_length=100)
    is_active: Optional[bool] = None


class UserLogin(BaseModel):
    """Schema for user login request."""

    email: EmailStr
    password: str
    mfa_code: Optional[str] = Field(None, description="MFA code if MFA is enabled")


class TokenResponse(BaseModel):
    """Schema for token response."""

    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int


class TokenRefresh(BaseModel):
    """Schema for token refresh request."""

    refresh_token: str


class PasswordChange(BaseModel):
    """Schema for password change request."""

    current_password: str
    new_password: str = Field(
        ...,
        min_length=12,
        description="Password must be at least 12 characters with uppercase, lowercase, numbers, and symbols",
    )


class PasswordReset(BaseModel):
    """Schema for password reset request."""

    email: EmailStr


class PasswordResetConfirm(BaseModel):
    """Schema for password reset confirmation."""

    token: str
    new_password: str = Field(
        ...,
        min_length=12,
        description="Password must be at least 12 characters with uppercase, lowercase, numbers, and symbols",
    )


class MFAEnable(BaseModel):
    """Schema for MFA enablement request."""

    password: str


class MFAVerify(BaseModel):
    """Schema for MFA code verification."""

    code: str = Field(..., min_length=6, max_length=6)


class TokenPayload(BaseModel):
    """Schema for JWT token payload."""

    sub: str
    email: str
    role: RoleType
    portal: PortalType
    permissions: List[str]
    exp: datetime
    iat: datetime


class UserResponse(UserBase):
    """Schema for user response (without sensitive data)."""

    id: int
    role: RoleType
    portal: PortalType
    mfa_enabled: bool
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True
