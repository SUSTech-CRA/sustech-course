from __future__ import annotations

import hashlib
import json
import urllib.parse
import uuid
from datetime import datetime

import httpx
from faker import Faker
from fastapi import HTTPException, status
from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.config import settings
from app.core.security import (
    create_access_token,
    create_refresh_token,
    create_timed_token,
    decode_token,
    token_matches_password,
    verify_timed_token,
)
from app.models import RevokedToken, Teacher, ThirdPartySigninHistory, User
from app.schemas.auth import RegisterRequest, TokenResponse
from app.utils.email import send_confirm_mail, send_reset_password_mail

EMAIL_CONFIRM_SALT = "email-confirm"
PASSWORD_RESET_SALT = "password-reset"
OAUTH_STATE_SALT = "oauth-state"
OAUTH_STATE_MAX_AGE_SECONDS = 10 * 60

_faker = Faker()


def generate_unique_username(db: Session) -> str:
    """Generate a random, non-identifying display name (never derived from a real name)."""
    base = _faker.name().replace(" ", "_")[:30]
    username = base
    suffix = 1
    while db.query(User).filter(User.username == username).first():
        username = f"{base[:25]}_{suffix}"
        suffix += 1
    return username


def _identity_from_email(email: str) -> str:
    if email.endswith("@mail.sustech.edu.cn"):
        return "Student"
    if email.endswith("@sustech.edu.cn"):
        return "Teacher"
    raise HTTPException(status_code=422, detail="必须使用南科大学生或教师邮箱注册")


async def verify_turnstile(token: str | None) -> bool:
    if not settings.RECAPTCHA_SECRET_KEY:
        return True
    if not token:
        return False
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            response = await client.post(
                settings.TURNSTILE_VERIFY_URL,
                data={"secret": settings.RECAPTCHA_SECRET_KEY, "response": token},
            )
        response.raise_for_status()
        return bool(response.json().get("success"))
    except Exception:
        return False


def issue_tokens(user: User, remember: bool = False) -> TokenResponse:
    return TokenResponse(
        access_token=create_access_token(user.id, user.password, remember=remember),
        refresh_token=create_refresh_token(user.id, user.password, remember=remember),
    )


def change_password(
    db: Session, user: User, old_password: str, new_password: str, *, remember: bool = False
) -> TokenResponse:
    if not user.check_password(old_password):
        raise HTTPException(status_code=400, detail="原密码不正确")
    user.set_password(new_password)
    db.add(user)
    db.commit()
    # 新哈希使其他设备上的令牌全部失效；为当前设备换发一对新令牌，保持登录
    return issue_tokens(user, remember=remember)


def authenticate_user(db: Session, login: str, password: str) -> User:
    user, authenticated, confirmed = User.authenticate(db, login, password)
    if not user or user.is_deleted or not authenticated:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="用户名或密码错误")
    if user.active is False:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="账号已被停用，请联系管理员")
    if not confirmed:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="请先激活邮箱")
    user.last_login_time = datetime.utcnow()
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


async def register_user(db: Session, payload: RegisterRequest) -> User:
    if not await verify_turnstile(payload.turnstile_token):
        raise HTTPException(status_code=400, detail="验证码错误，请重试")

    exists = (
        db.query(User)
        .filter(or_(User.username == payload.username, User.email == str(payload.email)))
        .first()
    )
    if exists and exists.username == payload.username:
        raise HTTPException(status_code=409, detail="该用户名已被注册，请选择其他用户名")
    if exists:
        raise HTTPException(status_code=409, detail="该邮箱已被注册，请使用其他邮箱")

    user = User(username=payload.username, email=str(payload.email), password="")
    user.set_password(payload.password)
    user.identity = _identity_from_email(str(payload.email))
    if user.identity == "Teacher":
        teacher = db.query(Teacher).filter(Teacher.email == str(payload.email)).first()
        if teacher:
            user.teacher_info = teacher
            user.description = teacher.description
            user.homepage = teacher.homepage

    db.add(user)
    db.commit()
    db.refresh(user)

    await send_confirm_mail(user.email, create_email_confirm_token(user.email))
    return user


def create_email_confirm_token(email: str) -> str:
    return create_timed_token(email, EMAIL_CONFIRM_SALT)


def create_password_reset_token(email: str) -> str:
    return create_timed_token(email, PASSWORD_RESET_SALT)


def _allowed_frontend_origin(origin: str | None) -> str:
    # OAuth 回跳目标与 CORS 是同一批浏览器 origin，白名单直接从配置派生，
    # 换域名时只需覆盖 CORS_ORIGINS / FRONTEND_BASE_URL 环境变量
    allowed = {item.rstrip("/") for item in settings.CORS_ORIGINS or []}
    allowed.add(settings.FRONTEND_BASE_URL.rstrip("/"))
    normalized = (origin or "").rstrip("/")
    return normalized if normalized in allowed else settings.FRONTEND_BASE_URL.rstrip("/")


def create_oauth_state(next_url: str | None = None, frontend_origin: str | None = None) -> str:
    payload = {
        "nonce": uuid.uuid4().hex,
        "next": next_url if next_url and next_url.startswith("/") else "/",
        "frontend_origin": _allowed_frontend_origin(frontend_origin),
    }
    return create_timed_token(json.dumps(payload), OAUTH_STATE_SALT)


def verify_oauth_state(state: str | None) -> dict[str, str]:
    if not state:
        raise HTTPException(status_code=400, detail="OAuth state 缺失")
    raw = verify_timed_token(state, OAUTH_STATE_SALT, OAUTH_STATE_MAX_AGE_SECONDS)
    if not raw:
        raise HTTPException(status_code=400, detail="OAuth state 无效或已过期")
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=400, detail="OAuth state 格式错误") from exc
    return {
        "next": data.get("next") if str(data.get("next", "")).startswith("/") else "/",
        "frontend_origin": _allowed_frontend_origin(data.get("frontend_origin")),
    }


def is_token_revoked(db: Session, token: str) -> bool:
    return db.get(RevokedToken, _token_fingerprint(token)) is not None


def revoke_token(db: Session, token: str) -> None:
    if not is_token_revoked(db, token):
        db.add(RevokedToken(value=_token_fingerprint(token)))
        db.commit()


def _token_fingerprint(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def confirm_email(db: Session, token: str) -> User:
    if is_token_revoked(db, token):
        raise HTTPException(status_code=400, detail="此激活链接已被使用过")
    email = verify_timed_token(token, EMAIL_CONFIRM_SALT, settings.EMAIL_TOKEN_EXPIRE_SECONDS)
    if not email:
        raise HTTPException(status_code=400, detail="此激活链接无效或已过期")
    user = db.query(User).filter(User.email == email).first()
    if not user:
        raise HTTPException(status_code=404, detail="用户不存在")
    user.confirm()
    db.add(user)
    db.add(RevokedToken(value=_token_fingerprint(token)))
    db.commit()
    db.refresh(user)
    return user


async def resend_confirmation(db: Session, login: str) -> None:
    user = db.query(User).filter(or_(User.email == login, User.username == login)).first()
    if not user:
        raise HTTPException(status_code=404, detail="用户不存在")
    if not user.confirmed:
        await send_confirm_mail(user.email, create_email_confirm_token(user.email))


async def send_password_reset(db: Session, email: str, turnstile_token: str | None) -> None:
    if not await verify_turnstile(turnstile_token):
        raise HTTPException(status_code=400, detail="验证码错误，请重试")
    user = db.query(User).filter(User.email == email).first()
    if not user:
        raise HTTPException(status_code=404, detail="此邮件地址尚未被注册")
    await send_reset_password_mail(email, create_password_reset_token(email))


def reset_password(db: Session, token: str, password: str) -> None:
    if is_token_revoked(db, token):
        raise HTTPException(status_code=400, detail="此密码重置链接已被使用过")
    email = verify_timed_token(token, PASSWORD_RESET_SALT, settings.EMAIL_TOKEN_EXPIRE_SECONDS)
    if not email:
        raise HTTPException(status_code=400, detail="此密码重置链接无效或已过期")
    user = db.query(User).filter(User.email == email).first()
    if not user:
        raise HTTPException(status_code=404, detail="用户不存在")
    user.set_password(password)
    db.add(user)
    db.add(RevokedToken(value=_token_fingerprint(token)))
    db.commit()


def refresh_access_token(db: Session, refresh_token: str) -> TokenResponse:
    if is_token_revoked(db, refresh_token):
        raise HTTPException(status_code=401, detail="refresh token 已失效")
    payload = decode_token(refresh_token, expected_type="refresh")
    if not payload or not payload.get("sub"):
        raise HTTPException(status_code=401, detail="refresh token 无效")
    user = db.get(User, int(payload["sub"]))
    if not user or user.is_deleted or user.active is False:
        raise HTTPException(status_code=401, detail="用户不存在或已停用")
    if not token_matches_password(payload, user.password):
        raise HTTPException(status_code=401, detail="登录状态已失效，请重新登录")
    revoke_token(db, refresh_token)
    return issue_tokens(user, remember=bool(payload.get("remember")))


def create_oauth_authorize_url(state: str) -> str:
    if not (settings.OAUTH_CLIENT_ID and settings.OAUTH_AUTH_URL and settings.OAUTH_REDIRECT_URI):
        raise HTTPException(status_code=503, detail="OAuth 未配置")
    query = {
        "response_type": "code",
        "client_id": settings.OAUTH_CLIENT_ID,
        "redirect_uri": settings.OAUTH_REDIRECT_URI,
        "scope": settings.OAUTH_SCOPE,
        "state": state,
    }
    return f"{settings.OAUTH_AUTH_URL}?{urllib.parse.urlencode(query)}"


def _bind_teacher_profile(db: Session, user: User) -> None:
    if user.identity != "Teacher":
        return
    teacher = db.query(Teacher).filter(Teacher.email == user.email).first()
    if not teacher:
        return
    user.teacher_info = teacher
    user.description = user.description or teacher.description
    user.homepage = user.homepage or teacher.homepage


async def handle_oauth_callback(db: Session, code: str) -> TokenResponse:
    if not (settings.OAUTH_CLIENT_ID and settings.OAUTH_CLIENT_SECRET and settings.OAUTH_TOKEN_URL):
        raise HTTPException(status_code=503, detail="OAuth 未配置")
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            token_response = await client.post(
                settings.OAUTH_TOKEN_URL,
                data={
                    "grant_type": "authorization_code",
                    "client_id": settings.OAUTH_CLIENT_ID,
                    "client_secret": settings.OAUTH_CLIENT_SECRET,
                    "code": code,
                    "redirect_uri": settings.OAUTH_REDIRECT_URI,
                },
            )
            token_response.raise_for_status()
            access_token = token_response.json().get("access_token")
            if not access_token:
                raise HTTPException(status_code=400, detail="SSO 登录凭证无效或已过期，请重新登录")
            profile_response = await client.get(
                settings.OAUTH_API_URL,
                headers={
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Authorization": f"Bearer {access_token}",
                },
            )
            profile_response.raise_for_status()
        profile = profile_response.json()
    except HTTPException:
        raise
    except httpx.HTTPStatusError as exc:
        # code 过期/被复用等上游 4xx 按客户端错误返回，其余按网关错误
        status_code = 400 if exc.response.status_code < 500 else 502
        raise HTTPException(status_code=status_code, detail="SSO 登录失败，请返回登录页重试") from exc
    except (httpx.HTTPError, ValueError) as exc:
        raise HTTPException(status_code=502, detail="SSO 服务暂时不可用，请稍后重试") from exc
    email = profile.get("email")
    if not email:
        raise HTTPException(status_code=400, detail="OAuth profile 中缺少 email")

    user = db.query(User).filter(User.email == email).first()
    if not user:
        # Always generate a random display name; never derive it from the SSO profile's
        # real name/preferred_username, to avoid leaking the user's real identity.
        username = generate_unique_username(db)
        user = User(username=username, email=email, password="")
        user.set_password(uuid.uuid4().hex)
        user.identity = _identity_from_email(email)
        _bind_teacher_profile(db, user)
        user.confirm()
        db.add(user)
        db.commit()
        db.refresh(user)
    else:
        _bind_teacher_profile(db, user)
    user.last_login_time = datetime.utcnow()
    db.add(user)
    db.commit()
    return issue_tokens(user)


def verify_3rdparty_credentials(
    db: Session,
    *,
    from_app: str,
    next_url: str,
    challenge: str,
    current_user: User | None,
    email: str | None,
    password: str | None,
) -> str:
    if current_user:
        user = current_user
    else:
        if not email or not password:
            raise HTTPException(status_code=422, detail="email 和 password 不能为空")
        user, authenticated, confirmed = User.authenticate_email(db, email, password)
        if not user or not authenticated:
            raise HTTPException(status_code=401, detail="邮箱地址或密码错误")
        if not confirmed:
            raise HTTPException(status_code=403, detail="账户未激活，请先点击邮箱里的激活链接")

    date = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    auth_str = (
        "challenge="
        + urllib.parse.quote(challenge)
        + "&date="
        + urllib.parse.quote(date)
        + "&email="
        + urllib.parse.quote(user.email)
        + "&status=200"
    )
    token = hashlib.sha256(auth_str.encode("utf-8")).hexdigest()
    user.token_3rdparty = token
    db.add(user)
    db.add(
        ThirdPartySigninHistory(
            user_id=user.id,
            email=user.email,
            from_app=from_app,
            next_url=next_url,
            challenge=challenge,
            token=token,
            signin_time=datetime.utcnow(),
            verify_time=None,
        )
    )
    db.commit()
    separator = "&" if "?" in next_url else "?"
    return f"{next_url}{separator}{auth_str}&token={token}"


def verify_3rdparty_token(db: Session, email: str, token: str) -> bool:
    user = db.query(User).filter(User.email == email).first()
    if not user or user.token_3rdparty != token:
        raise HTTPException(status_code=403, detail="user does not exist or token is invalid")
    user.token_3rdparty = None
    history = (
        db.query(ThirdPartySigninHistory)
        .filter(ThirdPartySigninHistory.email == email, ThirdPartySigninHistory.token == token)
        .first()
    )
    if history:
        history.verify_time = datetime.utcnow()
        db.add(history)
    db.add(user)
    db.commit()
    return True
