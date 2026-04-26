from uuid import UUID

from pydantic import BaseModel, EmailStr


class RegisterRequest(BaseModel):
    email: EmailStr
    password: str


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class UserPublic(BaseModel):
    id: UUID
    email: EmailStr


class AuthResponse(BaseModel):
    """Returned by /register and /login. Cookie is also set on the response."""

    token: str
    user: UserPublic