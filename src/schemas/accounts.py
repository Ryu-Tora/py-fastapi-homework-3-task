from pydantic import BaseModel, EmailStr, field_validator

from database import accounts_validators


class UserBase(BaseModel):
    email: EmailStr


class UserRegistrationRequestSchema(UserBase):
    password: str


class UserRegistrationResponseSchema(UserBase):
    id: int

    class Config:
        from_attributes = True


class Token(BaseModel):
    access_token: str
    token_type: str


class UserActivationRequestSchema(BaseModel):
    email: EmailStr
    token: str


class PasswordResetToken(BaseModel):
    email: EmailStr


class PasswordResetComplete(BaseModel):
    email: EmailStr
    token: str
    password: str


class UserLogin(BaseModel):
    email: EmailStr
    password: str


class UserRefreshToken(BaseModel):
    refresh_token: str


class UserAccessToken(BaseModel):
    access_token: str


class MessageResponseSchema(UserBase):
    pass
