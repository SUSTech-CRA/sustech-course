from datetime import timedelta

import pytest
from fastapi import HTTPException

from app.core.security import _create_token, create_access_token, create_refresh_token
from app.dependencies import get_optional_user
from app.models import User


class FakeSession:
    def __init__(self, users: dict[int, User] | None = None):
        self.users = users or {}

    def get(self, model, object_id):
        assert model is User
        return self.users.get(object_id)


def assert_invalid_token(token: str, db: FakeSession) -> None:
    with pytest.raises(HTTPException) as exc_info:
        get_optional_user(token=token, db=db)
    assert exc_info.value.status_code == 401
    assert exc_info.value.headers == {"WWW-Authenticate": 'Bearer error="invalid_token"'}


def test_optional_user_allows_missing_token() -> None:
    assert get_optional_user(token=None, db=FakeSession()) is None


def test_optional_user_returns_valid_active_user() -> None:
    user = User(id=42, active=True, is_deleted=False, password="hash")

    assert get_optional_user(token=create_access_token(user.id, user.password), db=FakeSession({user.id: user})) is user


def test_optional_user_rejects_expired_or_malformed_token() -> None:
    expired_token = _create_token(42, timedelta(seconds=-1), "access")

    assert_invalid_token(expired_token, FakeSession())
    assert_invalid_token("not-a-jwt", FakeSession())
    assert_invalid_token(create_refresh_token(42, "hash"), FakeSession())


def test_optional_user_rejects_missing_or_inactive_subject() -> None:
    inactive_user = User(id=42, active=False, is_deleted=False, password="hash")

    assert_invalid_token(create_access_token(404, "hash"), FakeSession())
    assert_invalid_token(create_access_token(inactive_user.id, inactive_user.password), FakeSession({inactive_user.id: inactive_user}))
