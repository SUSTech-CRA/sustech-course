from fastapi import APIRouter, HTTPException, Request

from app.config import settings
from app.core.rate_limit import create_exempt_token, identity_key
from app.schemas.auth import ChallengeRequest, ChallengeResponse
from app.services.auth_service import verify_turnstile

router = APIRouter()


@router.post("", response_model=ChallengeResponse)
async def solve_challenge(payload: ChallengeRequest, request: Request) -> ChallengeResponse:
    if not await verify_turnstile(payload.turnstile_token):
        raise HTTPException(status_code=422, detail="人机验证未通过，请重试")
    return ChallengeResponse(
        exempt_token=create_exempt_token(identity_key(request)),
        expires_in=settings.RATE_LIMIT_EXEMPT_MINUTES * 60,
    )
