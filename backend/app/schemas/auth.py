from pydantic import BaseModel, EmailStr, Field, field_validator, model_validator

from app.utils.username import normalize_username, validate_username_value


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=255)
    password: str = Field(min_length=1)
    remember: bool = False

    @field_validator("username")
    @classmethod
    def strip_username(cls, value: str) -> str:
        return normalize_username(value)


class RegisterRequest(BaseModel):
    username: str = Field(min_length=1, max_length=30)
    email: EmailStr
    password: str = Field(min_length=8)
    confirm_password: str
    turnstile_token: str | None = None

    @field_validator("username")
    @classmethod
    def validate_username(cls, value: str) -> str:
        value = normalize_username(value)
        error = validate_username_value(value)
        if error:
            raise ValueError(error)
        return value

    @field_validator("email")
    @classmethod
    def validate_sustech_email(cls, value: EmailStr) -> EmailStr:
        email = str(value)
        if not (email.endswith("@mail.sustech.edu.cn") or email.endswith("@sustech.edu.cn")):
            raise ValueError("必须使用南科大邮箱注册!")
        if email.split("@", 1)[0].startswith("list-"):
            raise ValueError("必须使用科大学生或教师邮箱注册")
        return value

    @model_validator(mode="after")
    def validate_passwords_match(self) -> "RegisterRequest":
        if self.password != self.confirm_password:
            raise ValueError("passwords must match")
        return self


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class AuthPublicConfig(BaseModel):
    turnstile_site_key: str = ""
    oauth_cra_enabled: bool = False
    oauth_cra_url: str = "/api/v1/auth/oauth/cra"


class RefreshRequest(BaseModel):
    refresh_token: str


class ConfirmEmailRequest(BaseModel):
    token: str


class ResendConfirmationRequest(BaseModel):
    # 用户名或邮箱均可（登录时用户可能只记得用户名）
    login: str = Field(min_length=1, max_length=255)


class ForgotPasswordRequest(BaseModel):
    email: EmailStr
    turnstile_token: str | None = None


class ResetPasswordRequest(BaseModel):
    token: str
    password: str = Field(min_length=8)
    confirm_password: str

    @model_validator(mode="after")
    def validate_passwords_match(self) -> "ResetPasswordRequest":
        if self.password != self.confirm_password:
            raise ValueError("passwords must match")
        return self


class ChangePasswordRequest(BaseModel):
    old_password: str = Field(min_length=1)
    new_password: str = Field(min_length=8)
    confirm_password: str

    @model_validator(mode="after")
    def validate_passwords_match(self) -> "ChangePasswordRequest":
        if self.new_password != self.confirm_password:
            raise ValueError("passwords must match")
        return self


class UsernameSuggestionResponse(BaseModel):
    username: str


class ChallengeRequest(BaseModel):
    turnstile_token: str | None = None


class ChallengeResponse(BaseModel):
    exempt_token: str
    expires_in: int


class ThirdPartySigninPage(BaseModel):
    from_app: str
    next_url: str
    challenge: str
    authenticated: bool


class ThirdPartyVerifyRequest(BaseModel):
    from_app: str
    next_url: str
    challenge: str
    email: str | None = None
    password: str | None = None


class ThirdPartyVerifyResponse(BaseModel):
    redirect_url: str


class ThirdPartyTokenVerifyResponse(BaseModel):
    success: bool
