from __future__ import annotations

import urllib.parse

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from fastapi.responses import RedirectResponse
from pydantic import ValidationError
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.security import decode_token
from app.dependencies import get_current_active_user, get_optional_user, oauth2_scheme
from app.models import User
from app.schemas.auth import (
    AuthPublicConfig,
    ChangePasswordRequest,
    ConfirmEmailRequest,
    ForgotPasswordRequest,
    LoginRequest,
    RefreshRequest,
    RegisterRequest,
    ResendConfirmationRequest,
    ResetPasswordRequest,
    ThirdPartySigninPage,
    ThirdPartyTokenVerifyResponse,
    ThirdPartyVerifyRequest,
    ThirdPartyVerifyResponse,
    TokenResponse,
    UsernameSuggestionResponse,
)
from app.config import settings
from app.schemas.common import MessageResponse
from app.schemas.user import UserResponse
from app.services.auth_service import (
    authenticate_user,
    change_password,
    confirm_email,
    create_oauth_state,
    create_oauth_authorize_url,
    generate_unique_username,
    handle_oauth_callback,
    issue_tokens,
    refresh_access_token,
    register_user,
    resend_confirmation,
    reset_password,
    revoke_token,
    send_password_reset,
    verify_oauth_state,
    verify_3rdparty_credentials,
    verify_3rdparty_token,
)

router = APIRouter()


@router.get("/public-config", response_model=AuthPublicConfig)
def public_config() -> AuthPublicConfig:
    return AuthPublicConfig(
        turnstile_site_key=settings.RECAPTCHA_SITE_KEY or "",
        oauth_cra_enabled=bool(
            settings.OAUTH_CLIENT_ID
            and settings.OAUTH_AUTH_URL
            and settings.OAUTH_REDIRECT_URI
        ),
    )


def serialize_user(user: User) -> UserResponse:
    return UserResponse(
        id=user.id,
        username=user.username,
        email=user.email,
        identity=user.identity,
        role=user.role,
        avatar=user.avatar,
        confirmed=user.confirmed,
        register_time=user.register_time,
        unread_notification_count=user.unread_notification_count or 0,
        student=user.student_info,
        teacher=user.teacher_info,
    )


async def parse_login_request(request: Request) -> LoginRequest:
    content_type = request.headers.get("content-type", "")
    try:
        if "application/x-www-form-urlencoded" in content_type or "multipart/form-data" in content_type:
            form = await request.form()
            return LoginRequest(
                username=str(form.get("username") or ""),
                password=str(form.get("password") or ""),
                remember=str(form.get("remember") or "").lower() in {"1", "true", "yes", "on"},
            )
        return LoginRequest.model_validate(await request.json())
    except ValidationError as exc:
        raise HTTPException(status_code=422, detail=exc.errors()) from exc
    except Exception as exc:
        raise HTTPException(status_code=400, detail="Invalid login request body") from exc


@router.post("/login", response_model=TokenResponse)
async def login(request: Request, db: Session = Depends(get_db)) -> TokenResponse:
    payload = await parse_login_request(request)
    user = authenticate_user(db, payload.username, payload.password)
    return issue_tokens(user, remember=payload.remember)


@router.post("/register", response_model=UserResponse, status_code=201)
async def register(payload: RegisterRequest, db: Session = Depends(get_db)) -> UserResponse:
    user = await register_user(db, payload)
    return serialize_user(user)


@router.get("/suggest-username", response_model=UsernameSuggestionResponse)
def suggest_username(db: Session = Depends(get_db)) -> UsernameSuggestionResponse:
    return UsernameSuggestionResponse(username=generate_unique_username(db))


@router.post("/logout", response_model=MessageResponse)
def logout(payload: RefreshRequest, db: Session = Depends(get_db)) -> MessageResponse:
    revoke_token(db, payload.refresh_token)
    return MessageResponse(ok=True, message="Logged out")


@router.post("/refresh", response_model=TokenResponse)
def refresh(payload: RefreshRequest, db: Session = Depends(get_db)) -> TokenResponse:
    return refresh_access_token(db, payload.refresh_token)


@router.get("/me", response_model=UserResponse)
def me(current_user: User = Depends(get_current_active_user)) -> UserResponse:
    return serialize_user(current_user)


@router.post("/change-password", response_model=TokenResponse)
def change_password_endpoint(
    payload: ChangePasswordRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
    token: str | None = Depends(oauth2_scheme),
) -> TokenResponse:
    # get_current_active_user 已校验过该 access token，这里只取 remember 以沿用当前会话时长
    remember = bool((decode_token(token or "", expected_type="access") or {}).get("remember"))
    return change_password(db, current_user, payload.old_password, payload.new_password, remember=remember)


@router.post("/confirm-email", response_model=MessageResponse)
def confirm_email_endpoint(
    payload: ConfirmEmailRequest, db: Session = Depends(get_db)
) -> MessageResponse:
    confirm_email(db, payload.token)
    return MessageResponse(ok=True, message="Your email has been confirmed")


@router.post("/resend-confirmation", response_model=MessageResponse)
async def resend_confirmation_endpoint(
    payload: ResendConfirmationRequest, db: Session = Depends(get_db)
) -> MessageResponse:
    await resend_confirmation(db, payload.login.strip())
    return MessageResponse(ok=True, message="邮件已经发送，请查收")


@router.post("/forgot-password", response_model=MessageResponse)
async def forgot_password(
    payload: ForgotPasswordRequest, db: Session = Depends(get_db)
) -> MessageResponse:
    await send_password_reset(db, str(payload.email), payload.turnstile_token)
    return MessageResponse(ok=True, message="密码重置邮件已发送")


@router.post("/reset-password", response_model=MessageResponse)
def reset_password_endpoint(
    payload: ResetPasswordRequest, db: Session = Depends(get_db)
) -> MessageResponse:
    reset_password(db, payload.token, payload.password)
    return MessageResponse(ok=True, message="密码已经修改，请使用新密码登录")


@router.get("/oauth/cra")
def oauth_cra(
    next: str | None = Query("/", alias="next"),
    frontend_origin: str | None = None,
) -> RedirectResponse:
    state = create_oauth_state(next, frontend_origin)
    return RedirectResponse(create_oauth_authorize_url(state))


@router.get("/oauth/cra/callback")
async def oauth_cra_callback(
    code: str,
    state: str | None = None,
    db: Session = Depends(get_db),
) -> RedirectResponse:
    # 浏览器重定向场景：SSO 上游/state 错误不抛 JSON，改为带提示跳回登录页
    try:
        state_data = verify_oauth_state(state)
    except HTTPException as exc:
        error_query = urllib.parse.urlencode({"oauth_error": exc.detail})
        return RedirectResponse(f"{settings.FRONTEND_BASE_URL.rstrip('/')}/signin?{error_query}")
    try:
        tokens = await handle_oauth_callback(db, code)
    except HTTPException as exc:
        error_query = urllib.parse.urlencode({"oauth_error": exc.detail})
        return RedirectResponse(f"{state_data['frontend_origin']}/signin?{error_query}")
    fragment = urllib.parse.urlencode(
        {
            "access_token": tokens.access_token,
            "refresh_token": tokens.refresh_token,
            "token_type": tokens.token_type,
            "next": state_data["next"],
        }
    )
    return RedirectResponse(f"{state_data['frontend_origin']}/oauth/cra/callback#{fragment}")


@router.get("/3rdparty/signin", response_model=ThirdPartySigninPage)
def signin_3rdparty_page(
    from_app: str = Query(...),
    next_url: str = Query(...),
    challenge: str = Query(...),
    current_user: User | None = Depends(get_optional_user),
) -> ThirdPartySigninPage:
    return ThirdPartySigninPage(
        from_app=from_app,
        next_url=next_url,
        challenge=challenge,
        authenticated=current_user is not None,
    )


@router.post("/3rdparty/verify", response_model=ThirdPartyVerifyResponse)
def signin_3rdparty_verify(
    payload: ThirdPartyVerifyRequest,
    response: Response,
    db: Session = Depends(get_db),
    current_user: User | None = Depends(get_optional_user),
) -> ThirdPartyVerifyResponse:
    redirect_url = verify_3rdparty_credentials(
        db,
        from_app=payload.from_app,
        next_url=payload.next_url,
        challenge=payload.challenge,
        current_user=current_user,
        email=payload.email,
        password=payload.password,
    )
    response.headers["Location"] = redirect_url
    return ThirdPartyVerifyResponse(redirect_url=redirect_url)


@router.get("/3rdparty/verify-token", response_model=ThirdPartyTokenVerifyResponse)
def verify_3rdparty_signin(
    email: str = Query(...),
    token: str = Query(...),
    db: Session = Depends(get_db),
) -> ThirdPartyTokenVerifyResponse:
    return ThirdPartyTokenVerifyResponse(success=verify_3rdparty_token(db, email, token))
