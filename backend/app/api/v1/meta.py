from datetime import datetime

from fastapi import APIRouter, Request

from app.schemas.common import RequestInfoResponse

router = APIRouter()


def _client_ip(request: Request) -> str | None:
    for header in ("cf-connecting-ip", "x-real-ip"):
        value = request.headers.get(header)
        if value:
            return value.strip()

    forwarded_for = request.headers.get("x-forwarded-for")
    if forwarded_for:
        return forwarded_for.split(",", 1)[0].strip()

    return request.client.host if request.client else None


@router.get("/request-info", response_model=RequestInfoResponse)
def request_info(request: Request) -> RequestInfoResponse:
    return RequestInfoResponse(server_time=datetime.utcnow(), client_ip=_client_ip(request))
