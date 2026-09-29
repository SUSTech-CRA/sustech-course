from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.schemas.stats import RankingsResponse, SiteStatsResponse
from app.services.stats_service import get_rankings, get_site_stats, get_stats_history

router = APIRouter()


@router.get("", response_model=SiteStatsResponse)
def site_stats(db: Session = Depends(get_db)):
    return get_site_stats(db)


@router.get("/rankings", response_model=RankingsResponse)
def rankings(limit: int = Query(50, ge=1, le=100), db: Session = Depends(get_db)):
    return get_rankings(db, limit)


@router.get("/history")
def stats_history(db: Session = Depends(get_db)):
    return get_stats_history(db)
