from datetime import datetime

from sqlalchemy import and_, extract, func
from sqlalchemy.orm import Session

from app.models import Course, CourseRate, Dept, Review, Teacher, User, course_teachers
from app.schemas.stats import (
    CourseRankingItem,
    DistributionPoint,
    RankingsResponse,
    RankingsStats,
    ReviewRankingItem,
    SeriesPoint,
    SiteStatsResponse,
    TeacherRankingItem,
    UserRankingItem,
)
from app.schemas.user import UserBrief
from app.services.course_service import serialize_course_brief
from app.services.user_service import serialize_user_brief
from app.utils.images import uploaded_image_url


def get_site_stats(db: Session) -> SiteStatsResponse:
    visible_filter = _visible_reviews_filter()
    review_count = db.query(Review).filter(*visible_filter).count()
    reviewed_course_count = (
        db.query(func.count(func.distinct(Review.course_id))).filter(*visible_filter).scalar() or 0
    )
    first_register_time = db.query(func.min(User.register_time)).scalar()
    course_avg_rate = db.query(func.avg(Review.rate)).filter(*visible_filter).scalar()

    return SiteStatsResponse(
        user_count=db.query(User).count(),
        course_count=db.query(Course).count(),
        review_count=review_count,
        teacher_count=db.query(Teacher).count(),
        registered_teacher_count=db.query(User).filter(User.identity == "Teacher").count(),
        running_days=(datetime.utcnow() - first_register_time).days if first_register_time else 0,
        course_avg_rate=float(course_avg_rate) if course_avg_rate is not None else None,
        course_avg_rate_count=review_count / reviewed_course_count if reviewed_course_count else None,
        review_rate_distribution=_review_rate_distribution(db),
        course_rate_distribution=_course_rate_distribution(db),
        course_review_count_distribution=_course_review_count_distribution(db),
        user_review_count_distribution=_user_review_count_distribution(db),
        review_monthly_distribution=_review_monthly_distribution(db),
        user_monthly_distribution=_user_monthly_distribution(db),
    )


def get_rankings(db: Session, limit: int = 50) -> RankingsResponse:
    limit = min(max(limit, 1), 100)
    stats = _ranking_stats(db)
    top_rated_courses = [
        _serialize_course_ranking(course, stats)
        for course in (
            db.query(Course)
            .join(CourseRate)
            .filter(CourseRate.review_count >= 10)
            .order_by(Course.QUERY_ORDER())
            .limit(limit)
            .all()
        )
    ]
    popular_courses = [
        _serialize_course_ranking(course, stats)
        for course in (
            db.query(Course)
            .join(CourseRate)
            .order_by(CourseRate.review_count.desc(), CourseRate._rate_average.desc(), Course.id.desc())
            .limit(limit)
            .all()
        )
    ]
    return RankingsResponse(
        stats=stats,
        top_teachers=_top_teachers(db, limit),
        top_rated_courses=top_rated_courses,
        popular_courses=popular_courses,
        top_reviews=_top_reviews(db, limit),
        long_reviews=_long_reviews(db, limit),
        top_users=_top_users(db, limit, stats),
    )


def get_stats_history(db: Session) -> dict:
    return {
        "site": get_site_stats(db),
        "rankings": get_rankings(db, limit=10),
    }


def _visible_reviews_filter():
    return Review.is_hidden.is_(False), Review.is_blocked.is_(False)


def _series_with_cumulative(rows: list[tuple[int, int]]) -> list[SeriesPoint]:
    remaining = sum(count for _, count in rows)
    points: list[SeriesPoint] = []
    for label, count in rows:
        points.append(SeriesPoint(label=str(label), value=int(count), cumulative=int(remaining)))
        remaining -= count
    return points


def _review_rate_distribution(db: Session) -> list[DistributionPoint]:
    rows = (
        db.query(Review.rate, func.count(Review.id))
        .filter(*_visible_reviews_filter(), Review.rate.isnot(None))
        .group_by(Review.rate)
        .order_by(Review.rate)
        .all()
    )
    return [DistributionPoint(label=str(rate), value=int(count)) for rate, count in rows]


def _course_rate_distribution(db: Session) -> list[DistributionPoint]:
    rows = (
        db.query(CourseRate._rate_average)
        .filter(CourseRate._rate_average.isnot(None), CourseRate._rate_average > 0)
        .all()
    )
    buckets: dict[str, int] = {}
    for (rate,) in rows:
        bucket = int(rate)
        label = "10" if bucket >= 10 else f"{bucket}-{bucket + 1}"
        buckets[label] = buckets.get(label, 0) + 1
    ordered = sorted(buckets.items(), key=lambda item: 10 if item[0] == "10" else int(item[0].split("-")[0]))
    return [DistributionPoint(label=label, value=value) for label, value in ordered]


def _course_review_count_distribution(db: Session) -> list[SeriesPoint]:
    course_review_counts = (
        db.query(Review.course_id, func.count(Review.id).label("review_count"))
        .filter(*_visible_reviews_filter())
        .group_by(Review.course_id)
        .subquery()
    )
    rows = (
        db.query(course_review_counts.c.review_count, func.count())
        .select_from(course_review_counts)
        .group_by(course_review_counts.c.review_count)
        .order_by(course_review_counts.c.review_count)
        .all()
    )
    return _series_with_cumulative([(int(review_count), int(course_count)) for review_count, course_count in rows])


def _user_review_count_distribution(db: Session) -> list[SeriesPoint]:
    user_review_counts = (
        db.query(Review.author_id, func.count(Review.id).label("review_count"))
        .filter(
            Review.is_anonymous.is_(False),
            *_visible_reviews_filter(),
        )
        .group_by(Review.author_id)
        .subquery()
    )
    rows = (
        db.query(user_review_counts.c.review_count, func.count())
        .select_from(user_review_counts)
        .group_by(user_review_counts.c.review_count)
        .order_by(user_review_counts.c.review_count)
        .all()
    )
    return _series_with_cumulative([(int(review_count), int(user_count)) for review_count, user_count in rows])


def _monthly_distribution(db: Session, date_column, count_column, filters=()) -> list[SeriesPoint]:
    year_expr = extract("year", date_column)
    month_expr = extract("month", date_column)
    rows = (
        db.query(year_expr.label("year"), month_expr.label("month"), func.count(count_column).label("count"))
        .filter(date_column.isnot(None), *filters)
        .group_by(year_expr, month_expr)
        .order_by(year_expr, month_expr)
        .all()
    )
    total = 0
    points: list[SeriesPoint] = []
    for row in rows:
        year = int(row.year)
        month = int(row.month)
        count = int(row.count)
        total += count
        points.append(SeriesPoint(label=f"{year}-{month:02d}", value=count, cumulative=total))
    return points


def _review_monthly_distribution(db: Session) -> list[SeriesPoint]:
    return _monthly_distribution(db, Review.publish_time, Review.id, _visible_reviews_filter())


def _user_monthly_distribution(db: Session) -> list[SeriesPoint]:
    return _monthly_distribution(db, User.register_time, User.id)


def _ranking_stats(db: Session) -> RankingsStats:
    visible_filter = _visible_reviews_filter()
    avg_rate = db.query(func.coalesce(func.avg(Review.rate), 0)).filter(*visible_filter).scalar() or 0
    avg_rate_count = (
        db.query(
            func.coalesce(
                func.count(Review.id) / func.nullif(func.count(func.distinct(Review.course_id)), 0),
                0,
            )
        )
        .filter(*visible_filter)
        .scalar()
        or 0
    )
    avg_review_upvotes = (
        db.query(func.coalesce(func.sum(Review.upvote_count) / func.nullif(func.count(Review.id), 0), 0))
        .filter(*visible_filter)
        .scalar()
        or 0
    )
    avg_review_length = (
        db.query(func.coalesce(func.sum(func.length(Review.content)) / func.nullif(func.count(Review.id), 0), 0))
        .filter(*visible_filter)
        .scalar()
        or 0
    )
    return RankingsStats(
        avg_rate=float(avg_rate),
        avg_rate_count=float(avg_rate_count),
        avg_review_upvotes=float(avg_review_upvotes),
        avg_review_length=float(avg_review_length),
    )


def _serialize_course_ranking(course: Course, stats: RankingsStats) -> CourseRankingItem:
    brief = serialize_course_brief(course).model_dump()
    rate = course.rate
    review_count = rate.review_count or 0
    normalized_rate = None
    if review_count:
        denominator = review_count + stats.avg_rate_count
        if denominator:
            normalized_rate = ((rate._rate_total or 0) + stats.avg_rate * stats.avg_rate_count) / denominator
    return CourseRankingItem(**brief, normalized_rate=normalized_rate)


def _top_teachers(db: Session, limit: int) -> list[TeacherRankingItem]:
    teachers_with_low_rating = (
        db.query(course_teachers.c.teacher_id)
        .join(CourseRate, course_teachers.c.course_id == CourseRate.id)
        .filter(CourseRate._rate_average > 0, CourseRate._rate_average < 8)
        .subquery()
    )
    teachers_with_enough_high_courses = (
        db.query(course_teachers.c.teacher_id.label("teacher_id"))
        .join(CourseRate, course_teachers.c.course_id == CourseRate.id)
        .filter(CourseRate._rate_average > 9)
        .group_by(course_teachers.c.teacher_id)
        .having(func.count(CourseRate.id) >= 3)
        .subquery()
    )
    normalized_rate = Course.generic_query_order(func.coalesce(func.sum(Review.rate), 0), func.count(Review.id)).label(
        "normalized_rate"
    )
    rows = (
        db.query(
            Teacher.id,
            Teacher.name,
            Dept.name.label("dept"),
            func.count(func.distinct(Course.id)).label("course_count"),
            func.count(Review.id).label("review_count"),
            normalized_rate,
        )
        .join(course_teachers, course_teachers.c.teacher_id == Teacher.id)
        .join(Course, Course.id == course_teachers.c.course_id)
        .outerjoin(Dept, Dept.id == Course.dept_id)
        .outerjoin(Review, and_(Review.course_id == Course.id, *_visible_reviews_filter()))
        .filter(Teacher.id.in_(db.query(teachers_with_enough_high_courses.c.teacher_id)))
        .filter(Teacher.id.notin_(db.query(teachers_with_low_rating.c.teacher_id)))
        .group_by(Teacher.id)
        .order_by(normalized_rate.desc())
        .limit(limit)
        .all()
    )
    return [
        TeacherRankingItem(
            id=row.id,
            name=row.name,
            dept=row.dept,
            course_count=row.course_count or 0,
            review_count=row.review_count or 0,
            normalized_rate=float(row.normalized_rate) if row.normalized_rate is not None else None,
        )
        for row in rows
    ]


def _review_rank_base(db: Session):
    return (
        db.query(
            Course.id.label("course_id"),
            Course.name.label("course_name"),
            Review.id.label("review_id"),
            User.id.label("author_id"),
            User.username.label("author_username"),
            User._avatar.label("author_avatar"),
            User.identity.label("author_identity"),
            Review.upvote_count.label("upvote_count"),
            Review.is_anonymous.label("is_anonymous"),
            func.length(Review.content).label("content_length"),
        )
        .select_from(Review)
        .join(User, User.id == Review.author_id)
        .join(Course, Course.id == Review.course_id)
        .filter(*_visible_reviews_filter(), Review.only_visible_to_student.is_(False))
    )


def _serialize_review_rank_row(row) -> ReviewRankingItem:
    author = None
    if not row.is_anonymous:
        author = UserBrief(
            id=row.author_id,
            username=row.author_username,
            avatar=uploaded_image_url(row.author_avatar, "/static/image/user.png"),
            identity=row.author_identity,
        )
    return ReviewRankingItem(
        course_id=row.course_id,
        course_name=row.course_name,
        review_id=row.review_id,
        author=author,
        author_name="匿名用户" if row.is_anonymous else row.author_username,
        is_anonymous=bool(row.is_anonymous),
        upvote_count=row.upvote_count or 0,
        content_length=row.content_length,
    )


def _top_reviews(db: Session, limit: int) -> list[ReviewRankingItem]:
    rows = (
        _review_rank_base(db)
        .filter(func.length(Review.content) >= 500)
        .order_by(Review.upvote_count.desc(), Review.id.desc())
        .limit(limit)
        .all()
    )
    return [_serialize_review_rank_row(row) for row in rows]


def _long_reviews(db: Session, limit: int) -> list[ReviewRankingItem]:
    rows = _review_rank_base(db).order_by(func.length(Review.content).desc(), Review.id.desc()).limit(limit).all()
    return [_serialize_review_rank_row(row) for row in rows]


def _top_users(db: Session, limit: int, stats: RankingsStats) -> list[UserRankingItem]:
    avg_upvotes = stats.avg_review_upvotes or 1
    avg_length = stats.avg_review_length or 1
    reviews_count = func.count(Review.id)
    upvotes_count = func.coalesce(func.sum(Review.upvote_count), 0)
    content_length = func.coalesce(func.sum(func.length(Review.content)), 0)
    score = (
        reviews_count
        + upvotes_count / (avg_upvotes * 5)
        + content_length / (avg_length * 5)
    ).label("score")
    rows = (
        db.query(
            User,
            reviews_count.label("reviews_count"),
            upvotes_count.label("review_upvotes_count"),
            content_length.label("review_length"),
            score,
        )
        .join(Review, Review.author_id == User.id)
        .filter(
            Review.is_anonymous.is_(False),
            Review.is_hidden.is_(False),
            Review.is_blocked.is_(False),
        )
        .group_by(User.id)
        .order_by(score.desc())
        .limit(limit)
        .all()
    )
    return [
        UserRankingItem(
            user=serialize_user_brief(row[0]),
            reviews_count=row.reviews_count or 0,
            review_upvotes_count=row.review_upvotes_count or 0,
            review_length=row.review_length or 0,
            score=float(row.score or 0),
        )
        for row in rows
    ]
