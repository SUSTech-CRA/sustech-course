from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.dependencies import get_current_active_user, get_optional_user
from app.models import User
from app.schemas.common import MessageResponse, PaginatedResponse
from app.schemas.course import CourseBrief
from app.schemas.review import ReviewResponse
from app.schemas.user import BindStudentRequest, NotificationResponse, UserBrief, UserProfile, UserUpdate
from app.services.notification_service import get_user_notifications, mark_all_as_read
from app.services.user_service import (
    bind_student,
    get_followers,
    get_following_courses,
    get_followings,
    get_joined_courses,
    get_user_profile,
    get_user_reviews,
    toggle_follow_user,
    update_profile,
)

router = APIRouter()


@router.patch("/me", response_model=UserProfile)
def update_me(payload: UserUpdate, db: Session = Depends(get_db), user: User = Depends(get_current_active_user)):
    return update_profile(db, user, payload)


@router.post("/me/bind-student", response_model=UserProfile)
def bind_me_student(payload: BindStudentRequest, db: Session = Depends(get_db), user: User = Depends(get_current_active_user)):
    return bind_student(db, user, payload.sno)


@router.get("/me/notifications", response_model=PaginatedResponse[NotificationResponse])
def my_notifications(
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_active_user),
):
    return get_user_notifications(db, user=user, page=page, per_page=per_page)


@router.post("/me/notifications/read-all", response_model=MessageResponse)
def read_notifications(db: Session = Depends(get_db), user: User = Depends(get_current_active_user)):
    mark_all_as_read(db, user)
    return MessageResponse(ok=True, message="Notifications marked as read")


@router.get("/{user_id}", response_model=UserProfile)
def user_profile(user_id: int, db: Session = Depends(get_db), viewer: User | None = Depends(get_optional_user)):
    return get_user_profile(db, user_id, viewer)


@router.get("/{user_id}/reviews", response_model=PaginatedResponse[ReviewResponse])
def user_reviews(
    user_id: int,
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
    viewer: User | None = Depends(get_optional_user),
):
    return get_user_reviews(db, user_id, viewer, page, per_page)


@router.get("/{user_id}/following-courses", response_model=PaginatedResponse[CourseBrief])
def user_following_courses(
    user_id: int,
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
    viewer: User | None = Depends(get_optional_user),
):
    user = get_user_profile(db, user_id, viewer)
    model_user = db.get(User, user.id)
    return get_following_courses(model_user, viewer, page, per_page)


@router.get("/{user_id}/joined-courses", response_model=PaginatedResponse[CourseBrief])
def user_joined_courses(
    user_id: int,
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_active_user),
):
    return get_joined_courses(db, user_id, user, page, per_page)


@router.get("/{user_id}/followers", response_model=PaginatedResponse[UserBrief])
def user_followers(
    user_id: int,
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
    viewer: User | None = Depends(get_optional_user),
):
    return get_followers(db, user_id, viewer, page, per_page)


@router.get("/{user_id}/followings", response_model=PaginatedResponse[UserBrief])
def user_followings(
    user_id: int,
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
    viewer: User | None = Depends(get_optional_user),
):
    return get_followings(db, user_id, viewer, page, per_page)


@router.post("/{user_id}/follow", response_model=UserProfile)
def follow_user_endpoint(user_id: int, db: Session = Depends(get_db), user: User = Depends(get_current_active_user)):
    return toggle_follow_user(db, user, user_id, True)


@router.delete("/{user_id}/follow", response_model=UserProfile)
def unfollow_user_endpoint(user_id: int, db: Session = Depends(get_db), user: User = Depends(get_current_active_user)):
    return toggle_follow_user(db, user, user_id, False)
