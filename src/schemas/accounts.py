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


class MessageResponseSchema(BaseModel):
    access_token: str
    token_type: str


class UserActivationRequestSchema(BaseModel):
    email: EmailStr
    token: str


class PasswordResetRequestSchema(BaseModel):
    email: EmailStr


class PasswordResetCompleteRequestSchema(BaseModel):
    email: EmailStr
    token: str
    password: str


class UserLoginResponseSchema(BaseModel):
    email: EmailStr
    password: str


class TokenRefreshRequestSchema(BaseModel):
    refresh_token: str


class UserAccessTokenResponseSchema(BaseModel):
    access_token: str


class UserLoginRequestSchema(BaseModel):
    pass


class TokenRefreshResponseSchema(BaseModel):
    pass


class UserLogin(BaseModel):
    pass


class UserRefreshToken(BaseModel):
    pass


class UserAccessToken(BaseModel):
    pass
