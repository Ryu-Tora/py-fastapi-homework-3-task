from pydantic import BaseModel, EmailStr, field_validator

from database import accounts_validators


class UserBase(BaseModel):
    email: EmailStr | str


class UserCreate(UserBase):
    password: str


class UserRead(UserBase):
    id: int

    class Config:
        from_attributes = True


class Token(BaseModel):
    access_token: str
    token_type: str


class ActivateAccount(BaseModel):
    email: str
    token: str


class PasswordResetToken(BaseModel):
    email: str


class PasswordResetComplete(BaseModel):
    email: str
    token: str
    password: str


class UserLogin(BaseModel):
    email: EmailStr
    password: str


class UserRefreshToken(BaseModel):
    refresh_token: str


class UserAccessToken(BaseModel):
    access_token: str
