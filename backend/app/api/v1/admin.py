from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.dependencies import get_admin_user
from app.models import Announcement, Banner, CourseReviewSummary, User
from app.schemas.admin import AnnouncementCreate, AnnouncementResponse, AnnouncementUpdate, BannerCreate, BannerResponse, CourseSummaryVisibilityUpdate
from app.schemas.common import MessageResponse

router = APIRouter()


@router.get("/banners/current", response_model=BannerResponse | None)
def current_banner(db: Session = Depends(get_db)):
    return db.query(Banner).order_by(Banner.publish_time.desc()).first()


@router.get("/banners", response_model=list[BannerResponse])
def list_banners(db: Session = Depends(get_db), _: User = Depends(get_admin_user)):
    return db.query(Banner).order_by(Banner.publish_time.desc()).all()


@router.post("/banners", response_model=BannerResponse, status_code=201)
def create_banner(payload: BannerCreate, db: Session = Depends(get_db), _: User = Depends(get_admin_user)):
    banner = Banner(**payload.model_dump(), publish_time=datetime.utcnow())
    db.add(banner)
    db.commit()
    db.refresh(banner)
    return banner


@router.get("/announcements", response_model=list[AnnouncementResponse])
def list_announcements(db: Session = Depends(get_db)):
    return db.query(Announcement).order_by(Announcement.update_time.desc()).all()


@router.post("/announcements", response_model=AnnouncementResponse, status_code=201)
def create_announcement(payload: AnnouncementCreate, db: Session = Depends(get_db), admin: User = Depends(get_admin_user)):
    now = datetime.utcnow()
    announcement = Announcement(
        **payload.model_dump(),
        author_id=admin.id,
        last_editor_id=admin.id,
        publish_time=now,
        update_time=now,
    )
    db.add(announcement)
    db.commit()
    db.refresh(announcement)
    return announcement


@router.patch("/announcements/{announcement_id}", response_model=AnnouncementResponse)
def update_announcement(announcement_id: int, payload: AnnouncementUpdate, db: Session = Depends(get_db), admin: User = Depends(get_admin_user)):
    announcement = db.get(Announcement, announcement_id)
    if not announcement:
        raise HTTPException(status_code=404, detail="Announcement not found")
    for key, value in payload.model_dump(exclude_unset=True).items():
        setattr(announcement, key, value)
    announcement.last_editor_id = admin.id
    announcement.update_time = datetime.utcnow()
    db.commit()
    db.refresh(announcement)
    return announcement


@router.delete("/announcements/{announcement_id}", response_model=MessageResponse)
def delete_announcement(announcement_id: int, db: Session = Depends(get_db), _: User = Depends(get_admin_user)):
    announcement = db.get(Announcement, announcement_id)
    if not announcement:
        raise HTTPException(status_code=404, detail="Announcement not found")
    db.delete(announcement)
    db.commit()
    return MessageResponse(ok=True, message="Announcement deleted")


@router.patch("/course-summaries/{course_id}/visibility", response_model=MessageResponse)
def update_course_summary_visibility(
    course_id: int,
    payload: CourseSummaryVisibilityUpdate,
    db: Session = Depends(get_db),
    _: User = Depends(get_admin_user),
):
    summary = db.get(CourseReviewSummary, course_id)
    if not summary:
        raise HTTPException(status_code=404, detail="Course summary not found")
    summary.is_hidden = payload.is_hidden
    db.commit()
    return MessageResponse(
        ok=True,
        message="Course summary hidden" if payload.is_hidden else "Course summary visible",
    )
