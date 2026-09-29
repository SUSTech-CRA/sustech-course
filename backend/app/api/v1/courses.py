from fastapi import APIRouter, Depends, Query
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.dependencies import get_admin_user, get_current_active_user, get_optional_user
from app.models import User
from app.schemas.common import PaginatedResponse
from app.schemas.course import (
    CourseBrief,
    CourseCreate,
    CourseDetail,
    CourseFilterOptions,
    CourseHistoryResponse,
    CourseMaterialDownloadResponse,
    CourseMaterialListResponse,
    CourseStats,
    CourseTeacherUpdate,
    CourseUpdate,
)
from app.schemas.enums import CourseSortBy, ReviewSortBy
from app.schemas.review import ReviewResponse
from app.services.course_service import (
    add_remove_teacher,
    create_or_update_course,
    find_course_id_by_code,
    get_course_filter_options,
    get_course_detail,
    get_course_history,
    get_course_list,
    get_course_stats,
    toggle_course_follow,
    toggle_course_join,
    toggle_course_vote,
)
from app.services.course_material_service import get_course_material_download_url, list_course_materials
from app.services.review_service import get_course_reviews

router = APIRouter()


@router.get("", response_model=PaginatedResponse[CourseBrief])
def list_courses(
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    sort_by: CourseSortBy = CourseSortBy.RATE,
    course_type: str | None = None,
    offering_unit: str | None = Query(None, max_length=100),
    db: Session = Depends(get_db),
):
    return get_course_list(
        db,
        page=page,
        per_page=per_page,
        sort_by=sort_by,
        course_type=course_type,
        offering_unit=offering_unit,
    )


@router.get("/filter-options", response_model=CourseFilterOptions)
def course_filter_options(db: Session = Depends(get_db)):
    return get_course_filter_options(db)


@router.get("/{course_id}", response_model=CourseDetail)
def course_detail(course_id: int, db: Session = Depends(get_db), user: User | None = Depends(get_optional_user)):
    return get_course_detail(db, course_id, user)


@router.post("", response_model=CourseDetail, status_code=201)
def create_course(payload: CourseCreate, db: Session = Depends(get_db), admin: User = Depends(get_admin_user)):
    return get_course_detail(db, create_or_update_course(db, payload=payload, course_id=None, author=admin).id, admin)


@router.patch("/{course_id}", response_model=CourseDetail)
def update_course(course_id: int, payload: CourseUpdate, db: Session = Depends(get_db), user: User = Depends(get_current_active_user)):
    return get_course_detail(db, create_or_update_course(db, payload=payload, course_id=course_id, author=user).id, user)


@router.get("/{course_id}/reviews", response_model=PaginatedResponse[ReviewResponse])
def course_reviews(
    course_id: int,
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    sort_by: ReviewSortBy = ReviewSortBy.PUBTIME_DESC,
    term: str | None = None,
    rating: int | None = Query(None, ge=1, le=10),
    db: Session = Depends(get_db),
    user: User | None = Depends(get_optional_user),
):
    return get_course_reviews(db, course_id=course_id, user=user, page=page, per_page=per_page, sort_by=sort_by, term=term, rating=rating)


@router.get("/{course_id}/stats", response_model=CourseStats)
def course_stats(course_id: int, db: Session = Depends(get_db)):
    return get_course_stats(db, course_id)


@router.get("/{course_id}/history", response_model=list[CourseHistoryResponse])
def course_history(course_id: int, db: Session = Depends(get_db), _: User = Depends(get_current_active_user)):
    return get_course_history(db, course_id)


@router.get("/by-code/{cno}")
def course_by_code(cno: str, term: int | None = None, db: Session = Depends(get_db)):
    return {"course_id": find_course_id_by_code(db, cno, term)}


@router.get("/{course_id}/materials", response_model=CourseMaterialListResponse)
def course_materials(
    course_id: int,
    path: str | None = None,
    db: Session = Depends(get_db),
    _: User = Depends(get_current_active_user),
):
    return list_course_materials(db, course_id, path)


@router.get("/{course_id}/materials/download")
def download_course_material(
    course_id: int,
    path: str,
    db: Session = Depends(get_db),
    _: User = Depends(get_current_active_user),
):
    return RedirectResponse(get_course_material_download_url(db, course_id, path))


@router.get("/{course_id}/materials/presign", response_model=CourseMaterialDownloadResponse)
def presign_course_material(
    course_id: int,
    path: str,
    db: Session = Depends(get_db),
    _: User = Depends(get_current_active_user),
):
    return CourseMaterialDownloadResponse(url=get_course_material_download_url(db, course_id, path))


@router.post("/{course_id}/upvote", response_model=CourseDetail)
def upvote_course(course_id: int, db: Session = Depends(get_db), user: User = Depends(get_current_active_user)):
    return toggle_course_vote(db, course_id, user, "upvote", True)


@router.delete("/{course_id}/upvote", response_model=CourseDetail)
def cancel_upvote_course(course_id: int, db: Session = Depends(get_db), user: User = Depends(get_current_active_user)):
    return toggle_course_vote(db, course_id, user, "upvote", False)


@router.post("/{course_id}/downvote", response_model=CourseDetail)
def downvote_course(course_id: int, db: Session = Depends(get_db), user: User = Depends(get_current_active_user)):
    return toggle_course_vote(db, course_id, user, "downvote", True)


@router.delete("/{course_id}/downvote", response_model=CourseDetail)
def cancel_downvote_course(course_id: int, db: Session = Depends(get_db), user: User = Depends(get_current_active_user)):
    return toggle_course_vote(db, course_id, user, "downvote", False)


@router.post("/{course_id}/follow", response_model=CourseDetail)
def follow_course(course_id: int, db: Session = Depends(get_db), user: User = Depends(get_current_active_user)):
    return toggle_course_follow(db, course_id, user, True)


@router.delete("/{course_id}/follow", response_model=CourseDetail)
def unfollow_course(course_id: int, db: Session = Depends(get_db), user: User = Depends(get_current_active_user)):
    return toggle_course_follow(db, course_id, user, False)


@router.post("/{course_id}/join", response_model=CourseDetail)
def join_course(course_id: int, db: Session = Depends(get_db), user: User = Depends(get_current_active_user)):
    return toggle_course_join(db, course_id, user, True)


@router.delete("/{course_id}/join", response_model=CourseDetail)
def quit_course(course_id: int, db: Session = Depends(get_db), user: User = Depends(get_current_active_user)):
    return toggle_course_join(db, course_id, user, False)


@router.post("/{course_id}/teachers", response_model=CourseDetail)
def add_teacher(course_id: int, payload: CourseTeacherUpdate, db: Session = Depends(get_db), _: User = Depends(get_admin_user)):
    return add_remove_teacher(db, course_id, payload.teacher_id, True)


@router.delete("/{course_id}/teachers/{teacher_id}", response_model=CourseDetail)
def remove_teacher(course_id: int, teacher_id: int, db: Session = Depends(get_db), _: User = Depends(get_admin_user)):
    return add_remove_teacher(db, course_id, teacher_id, False)
