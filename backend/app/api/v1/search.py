from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.dependencies import get_optional_user
from app.models import User
from app.schemas.enums import SearchType
from app.schemas.search import SearchSuggestResponse
from app.services.search_service import search_all, search_suggest

router = APIRouter()


@router.get("")
def search(
    q: str = Query(..., min_length=1),
    type: SearchType = SearchType.ALL,
    page: int = Query(1, ge=1),
    per_page: int = Query(10, ge=1, le=100),
    db: Session = Depends(get_db),
    user: User | None = Depends(get_optional_user),
):
    return search_all(db, q=q, search_type=type, user=user, page=page, per_page=per_page)


@router.get("/suggest", response_model=SearchSuggestResponse)
def suggest(
    q: str = Query(..., min_length=1, max_length=80),
    db: Session = Depends(get_db),
):
    # 击键级流量：限流走独立配额桶（core/rate_limit.py SUGGEST_PATH），不记 search_log
    return search_suggest(db, q)
