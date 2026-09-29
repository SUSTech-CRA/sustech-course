from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.security import decode_token, token_matches_password
from app.models import User

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login", auto_error=False)


def _credentials_exception(*, invalid_token: bool = False) -> HTTPException:
    authenticate = 'Bearer error="invalid_token"' if invalid_token else "Bearer"
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": authenticate},
    )


def _user_from_access_token(token: str, db: Session) -> User:
    payload = decode_token(token, expected_type="access")
    try:
        user_id = int(payload["sub"]) if payload and payload.get("sub") else None
    except (TypeError, ValueError):
        user_id = None
    if user_id is None:
        raise _credentials_exception(invalid_token=True)
    user = db.get(User, user_id)
    if user is None or user.is_deleted or user.active is False:
        raise _credentials_exception(invalid_token=True)
    if not token_matches_password(payload, user.password):
        raise _credentials_exception(invalid_token=True)
    return user


def get_optional_user(
    token: str | None = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
) -> User | None:
    if not token:
        return None
    return _user_from_access_token(token, db)


async def get_current_user(
    token: str | None = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
) -> User:
    if not token:
        raise _credentials_exception()
    return _user_from_access_token(token, db)


async def get_current_active_user(current_user: User = Depends(get_current_user)) -> User:
    if not current_user.confirmed:
        raise HTTPException(status_code=403, detail="Email not confirmed")
    return current_user


async def get_admin_user(current_user: User = Depends(get_current_active_user)) -> User:
    if current_user.role != "Admin":
        raise HTTPException(status_code=403, detail="Admin required")
    return current_user
