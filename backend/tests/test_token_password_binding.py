from datetime import timedelta

import pytest
from fastapi import HTTPException

from app.core.security import _create_token, create_refresh_token, decode_token
from app.dependencies import get_optional_user
from app.models import RevokedToken, User
from app.services.auth_service import change_password, issue_tokens, refresh_access_token


class FakeSession:
    def __init__(self, *users: User):
        self.users = {user.id: user for user in users}
        self.revoked: set[str] = set()

    def get(self, model, object_id):
        if model is RevokedToken:
            return object() if object_id in self.revoked else None
        assert model is User
        return self.users.get(object_id)

    def add(self, obj) -> None:
        if isinstance(obj, RevokedToken):
            self.revoked.add(obj.value)

    def commit(self) -> None:
        pass


def make_user(password: str = "old-password") -> User:
    user = User(id=7, active=True, is_deleted=False, password="")
    user.set_password(password)
    return user


def assert_refresh_rejected(db: FakeSession, token: str) -> None:
    with pytest.raises(HTTPException) as exc_info:
        refresh_access_token(db, token)
    assert exc_info.value.status_code == 401


def test_refresh_rotates_while_password_unchanged() -> None:
    user = make_user()
    db = FakeSession(user)
    tokens = issue_tokens(user, remember=True)

    rotated = refresh_access_token(db, tokens.refresh_token)

    assert decode_token(rotated.refresh_token, expected_type="refresh")["remember"] is True
    assert get_optional_user(token=rotated.access_token, db=db) is user
    assert_refresh_rejected(db, tokens.refresh_token)


def test_password_reset_invalidates_existing_tokens() -> None:
    user = make_user()
    db = FakeSession(user)
    tokens = issue_tokens(user)

    user.set_password("new-password")

    assert_refresh_rejected(db, tokens.refresh_token)
    with pytest.raises(HTTPException) as exc_info:
        get_optional_user(token=tokens.access_token, db=db)
    assert exc_info.value.status_code == 401


def test_change_password_reissues_tokens_for_current_session_only() -> None:
    user = make_user()
    db = FakeSession(user)
    other_device = issue_tokens(user, remember=True)

    current = change_password(db, user, "old-password", "new-password", remember=True)

    assert get_optional_user(token=current.access_token, db=db) is user
    assert decode_token(current.refresh_token, expected_type="refresh")["remember"] is True
    refresh_access_token(db, current.refresh_token)
    assert_refresh_rejected(db, other_device.refresh_token)


def test_tokens_without_password_stamp_are_rejected() -> None:
    user = make_user()
    db = FakeSession(user)
    legacy_refresh = _create_token(user.id, timedelta(days=1), "refresh", extra={"remember": False})
    legacy_access = _create_token(user.id, timedelta(minutes=5), "access")

    assert_refresh_rejected(db, legacy_refresh)
    with pytest.raises(HTTPException):
        get_optional_user(token=legacy_access, db=db)


def test_password_stamp_does_not_expose_hash() -> None:
    user = make_user()
    payload = decode_token(create_refresh_token(user.id, user.password), expected_type="refresh")

    assert payload["pwd_stamp"] not in user.password
    assert len(payload["pwd_stamp"]) == 16
