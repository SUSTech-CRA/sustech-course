from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from jose import JWTError, jwt
from werkzeug.security import check_password_hash, generate_password_hash

from app.config import settings


def verify_password(plain: str, hashed: str | None) -> bool:
    if not hashed:
        return False
    if hashed.startswith(("$2a$", "$2b$", "$2y$")):
        try:
            import bcrypt

            return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))
        except Exception:
            return False
    try:
        return check_password_hash(hashed, plain)
    except Exception:
        return False


def hash_password(password: str) -> str:
    # 共库过渡期必须固定 pbkdf2：老应用的 werkzeug 版本无法验证新版默认的 scrypt 哈希
    return generate_password_hash(password, method="pbkdf2:sha256")


def _create_token(user_id: int, expires_delta: timedelta, token_type: str, *, extra: dict[str, Any] | None = None) -> str:
    expire = datetime.now(timezone.utc) + expires_delta
    payload: dict[str, Any] = {"sub": str(user_id), "exp": expire, "type": token_type, **(extra or {})}
    return jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.JWT_ALGORITHM)


def create_access_token(user_id: int) -> str:
    return _create_token(
        user_id,
        timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES),
        "access",
    )


def create_refresh_token(user_id: int, remember: bool = False) -> str:
    days = settings.REMEMBER_REFRESH_TOKEN_EXPIRE_DAYS if remember else settings.REFRESH_TOKEN_EXPIRE_DAYS
    return _create_token(
        user_id,
        timedelta(days=days),
        "refresh",
        extra={"remember": remember},
    )


def decode_token(token: str, expected_type: str | None = None) -> dict[str, Any] | None:
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
    except JWTError:
        return None
    if expected_type and payload.get("type") != expected_type:
        return None
    return payload


def _serializer(salt: str) -> URLSafeTimedSerializer:
    return URLSafeTimedSerializer(settings.SECRET_KEY, salt=salt)


def create_timed_token(value: str, salt: str) -> str:
    return _serializer(salt).dumps(value)


def verify_timed_token(token: str, salt: str, max_age: int | None = None) -> str | None:
    try:
        return _serializer(salt).loads(token, max_age=max_age)
    except (BadSignature, SignatureExpired):
        return None
