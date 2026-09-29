from datetime import datetime

from fastapi import HTTPException
from sqlalchemy import func, update
from sqlalchemy.orm import Session

from app.models import Course, CourseRate, Review, Teacher, TeacherInfoHistory, User, course_teachers
from app.schemas.teacher import TeacherDetail, TeacherHistoryResponse, TeacherUpdate
from app.services import ugc_storage
from app.services.course_service import serialize_course_brief
from app.services.user_service import normalize_homepage, resolve_uploaded_image


def _teacher_courses_ranked(db: Session, teacher_id: int) -> list[Course]:
    """与老版 teacher.view_profile 一致：join course_rates 按归一化分排序，有点评的课程在前。"""
    return (
        db.query(Course)
        .join(course_teachers, Course.id == course_teachers.c.course_id)
        .filter(course_teachers.c.teacher_id == teacher_id)
        .join(CourseRate, Course.id == CourseRate.id)
        .order_by(Course.QUERY_ORDER())
        .all()
    )


def _teacher_stats(db: Session, courses: list[Course]) -> tuple[int, float, float]:
    """老版 teacher.py:31-42 的聚合统计：点评数、平均分、贝叶斯归一化分。"""
    review_count = sum(course.course_rate.review_count or 0 for course in courses)
    rate_total = sum(course.course_rate._rate_total or 0 for course in courses)
    average_rate = rate_total / review_count if review_count else 0.0
    normalized_rate = 0.0
    if courses:
        aggregate_filter = (Review.is_hidden.is_(False), Review.is_blocked.is_(False))
        avg_rate = db.query(func.avg(Review.rate)).filter(*aggregate_filter).scalar() or 0
        avg_rate_count = (
            db.query(func.count(Review.id) / func.nullif(func.count(func.distinct(Review.course_id)), 0))
            .filter(*aggregate_filter)
            .scalar()
            or 0
        )
        denominator = review_count + float(avg_rate_count)
        if denominator:
            normalized_rate = (rate_total + float(avg_rate) * float(avg_rate_count)) / denominator
    return review_count, float(average_rate), float(normalized_rate)


def get_teacher_detail(db: Session, teacher_id: int) -> TeacherDetail:
    teacher = db.get(Teacher, teacher_id)
    if not teacher:
        raise HTTPException(status_code=404, detail="Teacher not found")
    db.execute(
        update(Teacher)
        .where(Teacher.id == teacher.id)
        .values(access_count=func.coalesce(Teacher.access_count, 0) + 1)
    )
    db.commit()
    db.refresh(teacher)
    courses = _teacher_courses_ranked(db, teacher_id)
    review_count, average_rate, normalized_rate = _teacher_stats(db, courses)
    return TeacherDetail(
        id=teacher.id,
        name=teacher.name,
        email=teacher.email,
        title=teacher.title,
        image=teacher.image,
        dept_id=teacher.dept_id,
        office_phone=teacher.office_phone,
        gender=teacher.gender,
        description=teacher.description,
        homepage=teacher.homepage,
        research_interest=teacher.research_interest,
        access_count=teacher.access_count or 0,
        image_locked=bool(teacher.image_locked),
        info_locked=bool(teacher.info_locked),
        courses=[serialize_course_brief(course) for course in courses],
        review_count=review_count,
        average_rate=average_rate,
        normalized_rate=normalized_rate,
    )


def get_teacher_history(db: Session, teacher_id: int, user: User) -> list[TeacherHistoryResponse]:
    teacher = db.get(Teacher, teacher_id)
    if not teacher:
        raise HTTPException(status_code=404, detail="Teacher not found")
    if teacher.info_locked and not user.is_admin:
        raise HTTPException(status_code=403, detail="Teacher info is locked")
    history = (
        db.query(TeacherInfoHistory)
        .filter(TeacherInfoHistory.teacher_id == teacher_id)
        .order_by(TeacherInfoHistory.update_time.desc())
        .all()
    )
    return [TeacherHistoryResponse.model_validate(item) for item in history]


def update_teacher(db: Session, teacher_id: int, payload: TeacherUpdate, user: User) -> TeacherDetail:
    teacher = db.get(Teacher, teacher_id)
    if not teacher:
        raise HTTPException(status_code=404, detail="Teacher not found")
    data = payload.model_dump(exclude_unset=True)
    lock_fields = {"info_locked", "image_locked"}
    if not user.is_admin and lock_fields.intersection(data):
        raise HTTPException(status_code=403, detail="Only admins can change teacher locks")

    image_value = data.pop("image", None)
    info_data = {key: data.pop(key) for key in list(data) if key not in lock_fields}

    if info_data and teacher.info_locked and not user.is_admin:
        raise HTTPException(status_code=403, detail="Teacher info is locked")
    if image_value and teacher.image_locked and not user.is_admin:
        raise HTTPException(status_code=403, detail="Teacher photo is locked")

    if "homepage" in info_data:
        info_data["homepage"] = normalize_homepage(info_data["homepage"])
    for key, value in info_data.items():
        setattr(teacher, key, value)
    if image_value:
        teacher._image = ugc_storage.image_url(resolve_uploaded_image(db, image_value))
    if user.is_admin:
        for key in lock_fields.intersection(data):
            setattr(teacher, key, data[key])

    teacher.last_edit_time = datetime.utcnow()
    db.add(
        TeacherInfoHistory(
            teacher_id=teacher.id,
            author=user.id,
            update_time=datetime.utcnow(),
            _image=teacher._image,
            homepage=teacher.homepage,
            description=teacher.description,
            research_interest=teacher.research_interest,
        )
    )
    db.commit()
    return get_teacher_detail(db, teacher_id)
