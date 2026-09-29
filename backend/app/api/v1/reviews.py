from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.dependencies import get_admin_user, get_current_active_user, get_optional_user
from app.models import User
from app.schemas.common import MessageResponse, PaginatedResponse
from app.schemas.enums import ReviewFeedFilter, ReviewSortBy
from app.schemas.review import CommentCreate, CommentResponse, ReviewCreate, ReviewResponse, ReviewUpdate
from app.services.review_service import (
    add_comment,
    create_review,
    delete_comment,
    delete_review,
    get_comments,
    get_latest_reviews,
    get_review_detail,
    set_review_blocked,
    set_review_hidden,
    toggle_review_upvote,
    update_review,
)

router = APIRouter()


@router.get("", response_model=PaginatedResponse[ReviewResponse])
def list_reviews(
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    sort_by: ReviewSortBy = ReviewSortBy.UPDATETIME_DESC,
    filter: ReviewFeedFilter = ReviewFeedFilter.LATEST,
    db: Session = Depends(get_db),
    user: User | None = Depends(get_optional_user),
):
    return get_latest_reviews(db, user=user, page=page, per_page=per_page, sort_by=sort_by, feed_filter=filter)


@router.post("", response_model=ReviewResponse, status_code=201)
def create_review_endpoint(payload: ReviewCreate, db: Session = Depends(get_db), user: User = Depends(get_current_active_user)):
    return create_review(db, payload, user)


@router.get("/{review_id}", response_model=ReviewResponse)
def review_detail(review_id: int, db: Session = Depends(get_db), user: User | None = Depends(get_optional_user)):
    return get_review_detail(db, review_id, user)


@router.patch("/{review_id}", response_model=ReviewResponse)
def update_review_endpoint(review_id: int, payload: ReviewUpdate, db: Session = Depends(get_db), user: User = Depends(get_current_active_user)):
    return update_review(db, review_id, payload, user)


@router.delete("/{review_id}", response_model=MessageResponse)
def delete_review_endpoint(review_id: int, db: Session = Depends(get_db), user: User = Depends(get_current_active_user)):
    delete_review(db, review_id, user)
    return MessageResponse(ok=True, message="Review deleted")


@router.post("/{review_id}/upvote", response_model=ReviewResponse)
def upvote_review(review_id: int, db: Session = Depends(get_db), user: User = Depends(get_current_active_user)):
    return toggle_review_upvote(db, review_id, user, True)


@router.delete("/{review_id}/upvote", response_model=ReviewResponse)
def cancel_upvote_review(review_id: int, db: Session = Depends(get_db), user: User = Depends(get_current_active_user)):
    return toggle_review_upvote(db, review_id, user, False)


@router.post("/{review_id}/block", response_model=ReviewResponse)
def block_review(review_id: int, db: Session = Depends(get_db), admin: User = Depends(get_admin_user)):
    return set_review_blocked(db, review_id, admin, True)


@router.post("/{review_id}/unblock", response_model=ReviewResponse)
def unblock_review(review_id: int, db: Session = Depends(get_db), admin: User = Depends(get_admin_user)):
    return set_review_blocked(db, review_id, admin, False)


@router.post("/{review_id}/hide", response_model=ReviewResponse)
def hide_review(review_id: int, db: Session = Depends(get_db), user: User = Depends(get_current_active_user)):
    return set_review_hidden(db, review_id, user, True)


@router.post("/{review_id}/unhide", response_model=ReviewResponse)
def unhide_review(review_id: int, db: Session = Depends(get_db), user: User = Depends(get_current_active_user)):
    return set_review_hidden(db, review_id, user, False)


@router.get("/{review_id}/comments", response_model=list[CommentResponse])
def review_comments(review_id: int, db: Session = Depends(get_db), user: User | None = Depends(get_optional_user)):
    return get_comments(db, review_id, user)


@router.post("/{review_id}/comments", response_model=CommentResponse, status_code=201)
def add_review_comment(review_id: int, payload: CommentCreate, db: Session = Depends(get_db), user: User = Depends(get_current_active_user)):
    return add_comment(db, review_id, payload, user)


@router.delete("/comments/{comment_id}", response_model=MessageResponse)
def delete_review_comment(comment_id: int, db: Session = Depends(get_db), user: User = Depends(get_current_active_user)):
    delete_comment(db, comment_id, user)
    return MessageResponse(ok=True, message="Comment deleted")
