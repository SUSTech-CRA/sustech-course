from __future__ import annotations

from fastapi_mail import ConnectionConfig, FastMail, MessageSchema, MessageType
from pydantic import SecretStr

from app.config import settings


def _mail_config() -> ConnectionConfig:
    return ConnectionConfig(
        MAIL_USERNAME=settings.MAIL_USERNAME or "",
        MAIL_PASSWORD=SecretStr(settings.MAIL_PASSWORD or ""),
        MAIL_FROM=settings.MAIL_FROM,
        MAIL_PORT=settings.MAIL_PORT,
        MAIL_SERVER=settings.MAIL_SERVER,
        MAIL_FROM_NAME="NCES",
        MAIL_STARTTLS=settings.MAIL_USE_TLS,
        MAIL_SSL_TLS=settings.MAIL_USE_SSL,
        USE_CREDENTIALS=bool(settings.MAIL_USERNAME and settings.MAIL_PASSWORD),
        SUPPRESS_SEND=settings.MAIL_SUPPRESS_SEND,
        VALIDATE_CERTS=True,
    )


async def _send_mail(email: str, subject: str, html: str) -> None:
    message = MessageSchema(
        subject=subject,
        recipients=[email],
        body=html,
        subtype=MessageType.html,
    )
    await FastMail(_mail_config()).send_message(message)


async def send_confirm_mail(email: str, token: str) -> None:
    confirm_url = f"{settings.FRONTEND_BASE_URL}/confirm-email?token={token}"
    html = f"<p>请点击链接激活你的 NCES 账号：</p><p><a href=\"{confirm_url}\">{confirm_url}</a></p>"
    await _send_mail(email, "[NCES] Confirm your email.", html)


async def send_reset_password_mail(email: str, token: str) -> None:
    reset_url = f"{settings.FRONTEND_BASE_URL}/reset-password?token={token}"
    html = f"<p>请点击链接重置你的 NCES 密码：</p><p><a href=\"{reset_url}\">{reset_url}</a></p>"
    await _send_mail(email, "[NCES] Reset your password", html)


async def send_block_review_email(email: str, course_name: str) -> None:
    await _send_mail(
        email,
        f"[NCES] 您在课程「{course_name}」中的点评因违反社区规范，已被屏蔽",
        "<p>您的点评因违反社区规范，已被屏蔽。</p>",
    )


async def send_unblock_review_email(email: str, course_name: str) -> None:
    await _send_mail(
        email,
        f"[NCES] 您在课程「{course_name}」中的点评已被解除屏蔽",
        "<p>您的点评已被解除屏蔽。</p>",
    )
