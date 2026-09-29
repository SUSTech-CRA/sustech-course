from __future__ import annotations

from datetime import datetime
from math import ceil

from fastapi import HTTPException
from sqlalchemy import delete, distinct, func, or_, select, update
from sqlalchemy.orm import Session, object_session

from app.models import (
    Course,
    CourseClass,
    CourseInfoHistory,
    CourseRate,
    CourseTerm,
    Review,
    ReviewHistory,
    Teacher,
    User,
    course_teachers,
    downvote_course,
    follow_course,
    join_course,
    upvote_course,
)
from app.schemas.common import PaginatedResponse
from app.schemas.course import CourseBrief, CourseCreate, CourseDetail, CourseFilterOptions, CourseHistoryResponse, CourseStats, CourseTermStat, CourseUpdate, TeacherCourseGroup
from app.schemas.enums import CourseSortBy, ReviewSortBy
from app.utils.sanitize import sanitize


# 与老版 app/views/course.py:course_type_dict 一致的课程类别分组。
# 前端传分组 key，同时匹配 CourseTerm.course_type 或 join_type。
COURSE_TYPE_GROUPS: dict[str, list[str]] = {
    "public": ["公选课", "人文类", "任选", "国际化人才培养", "社科类", "艺术类"],
    "general": ["公共课（英语，思政）", "通识必修课"],
    "general-sci": ["通识基础课", "通识理工基础课", "通识选修课"],
    "major": ["专业课", "专业基础课", "专业必修课", "专业选修课", "专业核心课"],
    "practice-and-graduate": ["实践与毕业论文", "实践", "毕业设计/论文"],
}

# 课程目录里的开课单位存在少量明确的更名。筛选入口统一显示当前名称，
# 同时让旧名称下的历史课程仍可被找到。
OFFERING_UNIT_GROUPS: dict[str, list[str]] = {
    "社会科学中心暨社会科学高等研究院": ["社会科学中心暨社会科学高等研究院", "社会科学中心"],
    "自动化与智能制造学院": ["自动化与智能制造学院", "系统设计与智能制造学院"],
    "马克思主义学院": ["马克思主义学院", "思想政治教育与研究中心"],
}
OFFERING_UNIT_CANONICAL_NAMES = {
    alias: canonical
    for canonical, aliases in OFFERING_UNIT_GROUPS.items()
    for alias in aliases
}

# 课程详情页直接展开这些轻量关联列表；保留一个宽松的安全上限，避免异常数据
# 生成无界响应，同时不截断正常的同名课程、教师课程或开课记录。
COURSE_DETAIL_LIST_LIMIT = 999


def paginate(query, page: int, per_page: int):
    page = max(page, 1)
    per_page = min(max(per_page, 1), 100)
    total = query.count()
    items = query.offset((page - 1) * per_page).limit(per_page).all()
    return items, total, ceil(total / per_page) if total else 0


def serialize_course_brief(course: Course) -> CourseBrief:
    rate = course.rate
    return CourseBrief(
        id=course.id,
        name=course.name or "",
        course_code=course.course_code,
        teacher_names=course.teacher_names_display,
        term_ids=course.term_ids,
        review_count=rate.review_count or 0,
        rate_average=rate.rate_average,
        difficulty_score=rate.difficulty_score,
        homework_score=rate.homework_score,
        grading_score=rate.grading_score,
        gain_score=rate.gain_score,
    )


def _user_course_state(course: Course, user: User | None) -> dict[str, bool]:
    if not user:
        return {
            "is_upvoted": False,
            "is_downvoted": False,
            "is_following": False,
            "is_joined": False,
            "has_reviewed": False,
        }
    return {
        "is_upvoted": course in user.courses_upvoted,
        "is_downvoted": course in user.courses_downvoted,
        "is_following": course in user.courses_following,
        "is_joined": any(cls.course_id == course.id for cls in user.classes_joined),
        "has_reviewed": course in user.reviewed_course,
    }


def _related_courses(db: Session, course: Course, limit: int = COURSE_DETAIL_LIST_LIMIT) -> list[CourseBrief]:
    courses = (
        db.query(Course)
        .join(CourseRate)
        .filter(Course.name == course.name, Course.id != course.id)
        .order_by(Course.QUERY_ORDER(), Course.id.desc())
        .limit(limit)
        .all()
    )
    return [serialize_course_brief(item) for item in courses]


def _same_teacher_courses(db: Session, course: Course, limit: int = COURSE_DETAIL_LIST_LIMIT) -> list[TeacherCourseGroup]:
    groups: list[TeacherCourseGroup] = []
    for teacher in course.teachers:
        courses = (
            db.query(Course)
            .join(course_teachers, Course.id == course_teachers.c.course_id)
            .join(CourseRate)
            .filter(course_teachers.c.teacher_id == teacher.id, Course.id != course.id)
            .order_by(Course.QUERY_ORDER(), Course.id.desc())
            .limit(limit)
            .all()
        )
        if courses:
            groups.append(
                TeacherCourseGroup(
                    teacher=teacher,
                    courses=[serialize_course_brief(item) for item in courses],
                )
            )
    return groups


def serialize_course_detail(course: Course, user: User | None = None) -> CourseDetail:
    # 延迟导入避免 course_service ↔ review_service（集中可见性规则）的模块循环。
    from app.services.course_summary_service import serialize_visible_summary

    db = object_session(course)
    return CourseDetail(
        id=course.id,
        name=course.name or "",
        course_code=course.course_code,
        courseries=course.courseries,
        course_material_code=course.course_material_code,
        dept=course.dept,
        introduction=course.introduction,
        homepage=course.homepage,
        admin_announcement=course.admin_announcement,
        latest_score=course.latest_score,
        access_count=course.access_count or 0,
        teachers=course.teachers,
        credit=course.credit,
        hours=course.hours,
        hours_per_week=course.hours_per_week,
        description=course.description,
        description_eng=course.description_eng,
        teaching_material=course.teaching_material,
        reference_material=course.reference_material,
        student_requirements=course.student_requirements,
        campus=course.campus,
        course_major=course.course_major,
        course_type=course.course_type,
        grading_type=course.grading_type,
        rate=course.rate,
        review_term_list=course.review_term_list,
        terms=course.terms.limit(COURSE_DETAIL_LIST_LIMIT).all(),
        related_courses=_related_courses(db, course) if db else [],
        same_teacher_courses=_same_teacher_courses(db, course) if db else [],
        num_blocked_reviews=course.reviews.filter_by(is_blocked=True).count() if db else 0,
        num_deleted_reviews=_num_deleted_reviews(db, course.id) if db else 0,
        ai_summary=serialize_visible_summary(db, course.id) if db else None,
        **_user_course_state(course, user),
    )


def _num_deleted_reviews(db: Session, course_id: int) -> int:
    # 口径与老版 Course.num_deleted_reviews 一致：删除过点评的去重用户数
    return (
        db.query(func.count(distinct(ReviewHistory.author_id)))
        .filter(ReviewHistory.course_id == course_id, ReviewHistory.operation == "delete")
        .scalar()
        or 0
    )


def apply_course_order(query, sort_by: CourseSortBy):
    if sort_by == CourseSortBy.RATE:
        return query.join(CourseRate).order_by(Course.QUERY_ORDER())
    if sort_by == CourseSortBy.RATE_ASC:
        return query.join(CourseRate).order_by(Course.REVERSE_QUERY_ORDER())
    if sort_by == CourseSortBy.REVIEW_COUNT:
        return query.join(CourseRate).order_by(CourseRate.review_count.desc(), Course.id.desc())
    if sort_by == CourseSortBy.UPVOTE:
        return query.join(CourseRate).order_by(CourseRate.upvote_count.desc(), Course.id.desc())
    if sort_by == CourseSortBy.FOLLOW:
        return query.join(CourseRate).order_by(CourseRate.follow_count.desc(), Course.id.desc())
    if sort_by == CourseSortBy.JOIN:
        return query.join(CourseRate).order_by(CourseRate.join_count.desc(), Course.id.desc())
    return query.order_by(Course.name.asc(), Course.id.desc())


def _canonical_offering_unit(value: str) -> str:
    return OFFERING_UNIT_CANONICAL_NAMES.get(value, value)


def _latest_offering_unit():
    return (
        select(CourseTerm.course_major)
        .where(CourseTerm.course_id == Course.id)
        .order_by(CourseTerm.term.desc(), CourseTerm.id.desc())
        .limit(1)
        .correlate(Course)
        .scalar_subquery()
    )


def get_course_filter_options(db: Session) -> CourseFilterOptions:
    latest_terms = (
        db.query(
            CourseTerm.course_id.label("course_id"),
            func.max(CourseTerm.term).label("latest_term"),
        )
        .group_by(CourseTerm.course_id)
        .subquery()
    )
    values = (
        db.query(CourseTerm.course_major)
        .join(
            latest_terms,
            (CourseTerm.course_id == latest_terms.c.course_id)
            & (CourseTerm.term == latest_terms.c.latest_term),
        )
        .filter(CourseTerm.course_major.isnot(None), CourseTerm.course_major != "")
        .distinct()
        .all()
    )
    offering_units = sorted({_canonical_offering_unit(value) for (value,) in values})
    return CourseFilterOptions(offering_units=offering_units)


def get_course_list(
    db: Session,
    *,
    page: int,
    per_page: int,
    sort_by: CourseSortBy = CourseSortBy.RATE,
    course_type: str | None = None,
    offering_unit: str | None = None,
) -> PaginatedResponse[CourseBrief]:
    query = db.query(Course)
    if course_type:
        values = COURSE_TYPE_GROUPS.get(course_type)
        if values:
            query = query.filter(
                Course.terms.any(or_(CourseTerm.course_type.in_(values), CourseTerm.join_type.in_(values)))
            )
        else:
            # 兼容直接传数据库原始类别值
            query = query.filter(
                Course.terms.any(or_(CourseTerm.course_type == course_type, CourseTerm.join_type == course_type))
            )
    if offering_unit:
        unit_values = OFFERING_UNIT_GROUPS.get(offering_unit, [offering_unit])
        query = query.filter(_latest_offering_unit().in_(unit_values))
    query = apply_course_order(query, sort_by)
    items, total, pages = paginate(query, page, per_page)
    return PaginatedResponse(items=[serialize_course_brief(item) for item in items], total=total, page=page, per_page=per_page, pages=pages)


def get_course_detail(db: Session, course_id: int, user: User | None = None) -> CourseDetail:
    course = db.get(Course, course_id)
    if not course:
        raise HTTPException(status_code=404, detail="Course not found")
    db.execute(
        update(Course)
        .where(Course.id == course.id)
        .values(access_count=func.coalesce(Course.access_count, 0) + 1)
    )
    db.commit()
    db.refresh(course)
    return serialize_course_detail(course, user)


def create_or_update_course(
    db: Session,
    *,
    payload: CourseCreate | CourseUpdate,
    course_id: int | None,
    author: User,
) -> Course:
    course = db.get(Course, course_id) if course_id else Course()
    if not course:
        raise HTTPException(status_code=404, detail="Course not found")
    data = payload.model_dump(exclude_unset=True)
    if course_id is not None and not author.is_admin:
        allowed = {"introduction", "homepage"}
        disallowed = set(data) - allowed
        if disallowed:
            raise HTTPException(status_code=403, detail="Only course introduction and homepage can be edited")
    teacher_ids = data.pop("teacher_ids", None)
    if "homepage" in data and data["homepage"] is not None:
        homepage = data["homepage"].strip()
        if homepage and not homepage.startswith(("http://", "https://")):
            homepage = f"http://{homepage}"
        data["homepage"] = homepage
    if "introduction" in data:
        data["introduction"] = sanitize(data["introduction"])
    if "admin_announcement" in data:
        data["admin_announcement"] = sanitize(data["admin_announcement"])
    for key, value in data.items():
        setattr(course, key, value)
    course.last_edit_time = datetime.utcnow()
    db.add(course)
    db.flush()
    if not course._course_rate:
        db.add(CourseRate(id=course.id))
    if teacher_ids is not None:
        course.teachers = db.query(Teacher).filter(Teacher.id.in_(teacher_ids)).all() if teacher_ids else []
    db.add(
        CourseInfoHistory(
            course_id=course.id,
            author=author.id,
            update_time=datetime.utcnow(),
            introduction=course.introduction,
            homepage=course.homepage,
        )
    )
    db.commit()
    db.refresh(course)
    return course


def toggle_course_vote(db: Session, course_id: int, user: User, vote: str, enabled: bool) -> CourseDetail:
    course = db.get(Course, course_id)
    if not course:
        raise HTTPException(status_code=404, detail="Course not found")
    rate = course.lock_course_rate(db)
    upvote_pair = (upvote_course.c.course_id == course.id) & (upvote_course.c.user_id == user.id)
    downvote_pair = (downvote_course.c.course_id == course.id) & (downvote_course.c.user_id == user.id)
    if vote == "upvote":
        db.execute(delete(upvote_course).where(upvote_pair))
        if enabled:
            db.execute(upvote_course.insert().values(course_id=course.id, user_id=user.id))
            db.execute(delete(downvote_course).where(downvote_pair))
    elif vote == "downvote":
        db.execute(delete(downvote_course).where(downvote_pair))
        if enabled:
            db.execute(downvote_course.insert().values(course_id=course.id, user_id=user.id))
            db.execute(delete(upvote_course).where(upvote_pair))
    else:
        raise HTTPException(status_code=422, detail="Invalid vote")
    db.flush()
    rate.upvote_count = len(
        {
            user_id
            for (user_id,) in db.query(upvote_course.c.user_id)
            .filter(upvote_course.c.course_id == course.id)
            .with_for_update()
            .all()
        }
    )
    rate.downvote_count = len(
        {
            user_id
            for (user_id,) in db.query(downvote_course.c.user_id)
            .filter(downvote_course.c.course_id == course.id)
            .with_for_update()
            .all()
        }
    )
    db.commit()
    return serialize_course_detail(course, user)


def toggle_course_follow(db: Session, course_id: int, user: User, enabled: bool) -> CourseDetail:
    course = db.get(Course, course_id)
    if not course:
        raise HTTPException(status_code=404, detail="Course not found")
    rate = course.lock_course_rate(db)
    pair = (follow_course.c.course_id == course.id) & (follow_course.c.user_id == user.id)
    db.execute(delete(follow_course).where(pair))
    if enabled:
        db.execute(follow_course.insert().values(course_id=course.id, user_id=user.id))
    db.flush()
    rate.follow_count = len(
        {
            user_id
            for (user_id,) in db.query(follow_course.c.user_id)
            .filter(follow_course.c.course_id == course.id)
            .with_for_update()
            .all()
        }
    )
    db.commit()
    return serialize_course_detail(course, user)


def toggle_course_join(db: Session, course_id: int, user: User, enabled: bool) -> CourseDetail:
    if not user.is_student or not user.student_info:
        raise HTTPException(status_code=403, detail="Student identity required")
    course = db.get(Course, course_id)
    if not course:
        raise HTTPException(status_code=404, detail="Course not found")
    rate = course.lock_course_rate(db)
    student_id = user.student_info.sno
    joined_class_ids = [
        class_id
        for (class_id,) in db.query(join_course.c.class_id)
        .join(CourseClass, CourseClass.id == join_course.c.class_id)
        .filter(CourseClass.course_id == course.id, join_course.c.student_id == student_id)
        .with_for_update()
        .all()
    ]
    if enabled and not joined_class_ids:
        latest_class_id = (
            db.query(CourseClass.id)
            .filter(CourseClass.course_id == course.id)
            .order_by(CourseClass.term.desc(), CourseClass.id.desc())
            .with_for_update()
            .scalar()
        )
        if latest_class_id is None:
            raise HTTPException(status_code=404, detail="No course class found")
        db.execute(join_course.insert().values(class_id=latest_class_id, student_id=student_id))
    if not enabled and joined_class_ids:
        db.execute(
            delete(join_course).where(
                join_course.c.student_id == student_id,
                join_course.c.class_id.in_(joined_class_ids),
            )
        )
    db.flush()
    rate.join_count = len(
        {
            joined_student_id
            for (joined_student_id,) in db.query(join_course.c.student_id)
            .join(CourseClass, CourseClass.id == join_course.c.class_id)
            .filter(CourseClass.course_id == course.id)
            .with_for_update()
            .all()
        }
    )
    db.commit()
    return serialize_course_detail(course, user)


def add_remove_teacher(db: Session, course_id: int, teacher_id: int, enabled: bool) -> CourseDetail:
    course = db.get(Course, course_id)
    teacher = db.get(Teacher, teacher_id)
    if not course or not teacher:
        raise HTTPException(status_code=404, detail="Course or teacher not found")
    if enabled and teacher not in course.teachers:
        course.teachers.append(teacher)
    if not enabled and teacher in course.teachers:
        course.teachers.remove(teacher)
    db.commit()
    return serialize_course_detail(course)


def get_course_stats(db: Session, course_id: int) -> CourseStats:
    course = db.get(Course, course_id)
    if not course:
        raise HTTPException(status_code=404, detail="Course not found")
    # 课程页公开派生统计与 course_rates 口径一致：隐藏/屏蔽点评不参与。
    term_rows = (
        db.query(Review.term, func.count(Review.id), func.avg(Review.rate))
        .filter(
            Review.course_id == course.id,
            Review.is_hidden.is_(False),
            Review.is_blocked.is_(False),
            Review.term.isnot(None),
            Review.term != "",
        )
        .group_by(Review.term)
        .order_by(Review.term)
        .all()
    )
    return CourseStats(
        course_id=course.id,
        review_count=course.review_count,
        rating_distribution=dict(course.review_rate_dist),
        term_distribution=dict(course.review_term_dist),
        term_stats=[
            CourseTermStat(
                term=row[0],
                review_count=row[1],
                rate_average=float(row[2]) if row[2] is not None else None,
            )
            for row in term_rows
        ],
    )


def get_course_history(db: Session, course_id: int) -> list[CourseHistoryResponse]:
    course = db.get(Course, course_id)
    if not course:
        raise HTTPException(status_code=404, detail="Course not found")
    return [CourseHistoryResponse.model_validate(item) for item in course.info_history]


def find_course_id_by_code(db: Session, cno: str, term: int | None = None) -> int:
    cno = cno.strip()
    query = db.query(CourseClass).filter(CourseClass.cno == cno)
    if term is not None:
        query = query.filter(CourseClass.term == term)
    course_class = query.order_by(CourseClass.term.desc()).first()
    if not course_class:
        raise HTTPException(status_code=404, detail="Course not found")
    return course_class.course_id
