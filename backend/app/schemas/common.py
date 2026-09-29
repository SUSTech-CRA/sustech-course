from datetime import datetime
from typing import Generic, TypeVar

from pydantic import BaseModel

T = TypeVar("T")


class PaginatedResponse(BaseModel, Generic[T]):
    items: list[T]
    total: int
    page: int
    per_page: int
    pages: int


class MessageResponse(BaseModel):
    ok: bool
    message: str | None = None


class CountResponse(BaseModel):
    ok: bool
    count: int


class RequestInfoResponse(BaseModel):
    server_time: datetime
    client_ip: str | None = None
