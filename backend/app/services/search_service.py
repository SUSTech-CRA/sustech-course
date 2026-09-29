from __future__ import annotations

import logging
from html import escape as escape_html
from math import ceil

from sqlalchemy import and_, or_
from sqlalchemy.orm import Session

from app.config import settings
from app.models import Course, CourseRate, Review, SearchLog, Teacher, User
from app.schemas.common import PaginatedResponse
from app.schemas.course import CourseBrief
from app.schemas.enums import SearchType
from app.schemas.review import ReviewResponse
from app.schemas.search import SearchSuggestCourse, SearchSuggestResponse, SearchSuggestTeacher
from app.schemas.user import TeacherBrief
from app.search.documents import HIGHLIGHT_POST, HIGHLIGHT_PRE, INDEX_COURSES, INDEX_REVIEWS, INDEX_TEACHERS
from app.search.meili_client import get_query_client
from app.services.course_service import serialize_course_brief
from app.services.review_service import filter_reviews_by_visibility, serialize_review

logger = logging.getLogger(__name__)

_SUGGEST_COURSE_LIMIT = 5
_SUGGEST_TEACHER_LIMIT = 3


def _paginate(query, page: int, per_page: int):
    page = max(page, 1)
    per_page = min(max(per_page, 1), 100)
    total = query.count()
    items = query.offset((page - 1) * per_page).limit(per_page).all()
    return items, total, ceil(total / per_page) if total else 0


def _keywords(q: str) -> list[str]:
    return [item for item in q.split() if item]


def _meili_enabled() -> bool:
    return settings.SEARCH_ENGINE == "meilisearch" and bool(settings.MEILISEARCH_URL)


def _format_highlight(text: str) -> str:
    """Meilisearch _formatted 文本 → HTML 转义 + 哨兵换 <mark>，输出无 XSS 面。"""
    return escape_html(text).replace(HIGHLIGHT_PRE, "<mark>").replace(HIGHLIGHT_POST, "</mark>")


# ---------------------------------------------------------------------------
# SQL 路径（fallback）：Meilisearch 未启用或请求失败时使用，逻辑保持迁移初版原样
# ---------------------------------------------------------------------------


def search_courses(db: Session, q: str, page: int, per_page: int) -> PaginatedResponse[CourseBrief]:
    clauses = []
    for keyword in _keywords(q):
        pattern = f"%{keyword}%"
        clauses.append(
            or_(
                Course.name.ilike(pattern),
                Course.course_code.ilike(pattern),
                Teacher.name.ilike(pattern),
            )
        )
    query = db.query(Course).outerjoin(Course.teachers).outerjoin(CourseRate)
    if clauses:
        query = query.filter(and_(*clauses))
    query = query.distinct()
    items, total, pages = _paginate(
        query.order_by(
            (CourseRate.review_count > 0).desc(),
            Course.QUERY_ORDER(),
            CourseRate.review_count.desc(),
            Course.id.desc(),
        ),
        page,
        per_page,
    )
    return PaginatedResponse(items=[serialize_course_brief(item) for item in items], total=total, page=page, per_page=per_page, pages=pages)


def search_reviews(db: Session, q: str, user: User | None, page: int, per_page: int) -> PaginatedResponse[ReviewResponse]:
    clauses = []
    for keyword in _keywords(q):
        pattern = f"%{keyword}%"
        clauses.append(
            or_(
                Review.content.ilike(pattern),
                Course.name.ilike(pattern),
                Course.course_code.ilike(pattern),
                # 与老版一致：按作者用户名搜索时必须排除匿名点评与隐藏主页的用户，
                # 否则可以通过搜索用户名对匿名点评去匿名化。
                and_(
                    User.username.ilike(pattern),
                    Review.is_anonymous.is_(False),
                    User.is_profile_hidden.is_(False),
                ),
            )
        )
    # feed=True：搜索结果对所有人（含作者/管理员）隐藏 blocked/hidden，
    # 与老应用搜索行为及 Meilisearch 路径保持一致
    query = filter_reviews_by_visibility(db.query(Review), user, feed=True).outerjoin(Review.course).outerjoin(Review.author)
    if clauses:
        query = query.filter(and_(*clauses))
    items, total, pages = _paginate(query.order_by(Review.update_time.desc()), page, per_page)
    return PaginatedResponse(items=[serialize_review(item, user) for item in items], total=total, page=page, per_page=per_page, pages=pages)


def search_teachers(db: Session, q: str, page: int, per_page: int) -> PaginatedResponse[TeacherBrief]:
    clauses = []
    for keyword in _keywords(q):
        pattern = f"%{keyword}%"
        clauses.append(
            or_(
                Teacher.name.ilike(pattern),
                Teacher.email.ilike(pattern),
                Teacher.title.ilike(pattern),
                Teacher.research_interest.ilike(pattern),
            )
        )
    query = db.query(Teacher)
    if clauses:
        query = query.filter(and_(*clauses))
    items, total, pages = _paginate(query.order_by(Teacher.id.desc()), page, per_page)
    return PaginatedResponse(items=[TeacherBrief.model_validate(item) for item in items], total=total, page=page, per_page=per_page, pages=pages)


# ---------------------------------------------------------------------------
# Meilisearch 路径：索引只做 ID 召回与高亮，命中回 MySQL hydrate；
# 点评可见性一律在 DB 侧强制执行（索引滞后最多只造成相关性偏差，不可能泄露）
# ---------------------------------------------------------------------------


def _pages_for(total: int, per_page: int) -> int:
    return ceil(total / per_page) if total else 0


def _meili_search_courses(db: Session, q: str, page: int, per_page: int) -> PaginatedResponse[CourseBrief]:
    result = get_query_client().search(
        INDEX_COURSES,
        {
            "q": q,
            "page": max(page, 1),
            "hitsPerPage": per_page,
            "attributesToRetrieve": ["id"],
            "attributesToHighlight": ["name"],
            "highlightPreTag": HIGHLIGHT_PRE,
            "highlightPostTag": HIGHLIGHT_POST,
        },
    )
    ids = [hit["id"] for hit in result["hits"]]
    highlighted = {hit["id"]: hit.get("_formatted", {}).get("name", "") for hit in result["hits"]}
    courses = {course.id: course for course in db.query(Course).filter(Course.id.in_(ids)).all()} if ids else {}
    items = []
    for course_id in ids:
        course = courses.get(course_id)
        if not course:  # 索引滞后：课程已被删除
            continue
        brief = serialize_course_brief(course)
        if HIGHLIGHT_PRE in highlighted.get(course_id, ""):
            brief.name_highlighted = _format_highlight(highlighted[course_id])
        items.append(brief)
    total = result.get("totalHits", len(items))
    return PaginatedResponse(items=items, total=total, page=page, per_page=per_page, pages=_pages_for(total, per_page))


def _reviews_by_author_username(db: Session, q: str, user: User | None, limit: int) -> list[Review]:
    """整个查询串精确匹配用户名（老版行为）时补充该作者的点评。

    作者字段不进索引，匿名/主页隐藏的判断完全留在 DB 侧闭环。
    只在第一页置顶最多 limit 条（保持 per_page 语义），
    更多点评从结果里的作者链接进个人主页看。
    """
    username = q.strip()
    if not username or len(_keywords(q)) != 1:
        return []
    author = db.query(User).filter(User.username == username, User.is_profile_hidden.is_(False)).first()
    if not author:
        return []
    query = db.query(Review).filter(Review.author_id == author.id, Review.is_anonymous.is_(False))
    query = filter_reviews_by_visibility(query, user, feed=True)
    return query.order_by(Review.update_time.desc()).limit(limit).all()


def _meili_search_reviews(db: Session, q: str, user: User | None, page: int, per_page: int) -> PaginatedResponse[ReviewResponse]:
    params = {
        "q": q,
        "page": max(page, 1),
        "hitsPerPage": per_page,
        "attributesToRetrieve": ["id"],
        "attributesToHighlight": ["content"],
        "attributesToCrop": ["content"],
        "cropLength": 40,
        "highlightPreTag": HIGHLIGHT_PRE,
        "highlightPostTag": HIGHLIGHT_POST,
    }
    # 学生看全部；其余身份（含匿名/非学生/管理员）预过滤 only_visible_to_student，
    # 与 filter_reviews_by_visibility 的老版语义一致，同时保证分页每页条数精确
    if not (user and user.identity == "Student"):
        params["filter"] = "only_visible_to_student = false"
    result = get_query_client().search(INDEX_REVIEWS, params)

    ids = [hit["id"] for hit in result["hits"]]
    snippets = {hit["id"]: hit.get("_formatted", {}).get("content", "") for hit in result["hits"]}

    author_reviews = _reviews_by_author_username(db, q, user, limit=per_page) if page <= 1 else []
    author_ids = {review.id for review in author_reviews}

    hydrated: dict[int, Review] = {}
    if ids:
        # hydrate 时再过一遍可见性：索引滞后窗口内被屏蔽/隐藏/删除的点评在这里被拦掉
        query = filter_reviews_by_visibility(db.query(Review).filter(Review.id.in_(ids)), user, feed=True)
        hydrated = {review.id: review for review in query.all()}

    items: list[ReviewResponse] = []
    items.extend(serialize_review(review, user) for review in author_reviews)
    for review_id in ids:
        review = hydrated.get(review_id)
        if not review or review.id in author_ids:
            continue
        response = serialize_review(review, user)
        snippet = snippets.get(review_id, "")
        if HIGHLIGHT_PRE in snippet:
            response.content_snippet = _format_highlight(snippet)
        items.append(response)

    total = result.get("totalHits", 0) + len(author_reviews)
    return PaginatedResponse(items=items, total=total, page=page, per_page=per_page, pages=_pages_for(total, per_page))


def _meili_search_teachers(db: Session, q: str, page: int, per_page: int) -> PaginatedResponse[TeacherBrief]:
    result = get_query_client().search(
        INDEX_TEACHERS,
        {"q": q, "page": max(page, 1), "hitsPerPage": per_page, "attributesToRetrieve": ["id"]},
    )
    ids = [hit["id"] for hit in result["hits"]]
    teachers = {teacher.id: teacher for teacher in db.query(Teacher).filter(Teacher.id.in_(ids)).all()} if ids else {}
    items = [TeacherBrief.model_validate(teachers[teacher_id]) for teacher_id in ids if teacher_id in teachers]
    total = result.get("totalHits", len(items))
    return PaginatedResponse(items=items, total=total, page=page, per_page=per_page, pages=_pages_for(total, per_page))


# ---------------------------------------------------------------------------
# 对外入口
# ---------------------------------------------------------------------------


def _record_search_log(db: Session, q: str, user: User | None, search_type: SearchType, page: int) -> None:
    module = {
        SearchType.COURSE: "search_course",
        SearchType.REVIEW: "search_reviews",
        SearchType.TEACHER: "search_teacher",
    }.get(search_type, "search_all")
    db.add(SearchLog(keyword=q[:255], user_id=user.id if user else None, module=module, page=page))
    db.commit()


def _dispatch(
    db: Session,
    *,
    q: str,
    search_type: SearchType,
    user: User | None,
    page: int,
    per_page: int,
    use_meili: bool,
) -> dict:
    course_fn = _meili_search_courses if use_meili else search_courses
    teacher_fn = _meili_search_teachers if use_meili else search_teachers
    review_fn = _meili_search_reviews if use_meili else search_reviews
    if search_type == SearchType.COURSE:
        return {"courses": course_fn(db, q, page, per_page), "reviews": None, "teachers": None}
    if search_type == SearchType.REVIEW:
        return {"courses": None, "reviews": review_fn(db, q, user, page, per_page), "teachers": None}
    if search_type == SearchType.TEACHER:
        return {"courses": None, "reviews": None, "teachers": teacher_fn(db, q, page, per_page)}
    return {
        "courses": course_fn(db, q, page, min(per_page, 5)),
        "reviews": review_fn(db, q, user, page, min(per_page, 5)),
        "teachers": teacher_fn(db, q, page, min(per_page, 5)),
    }


def search_all(
    db: Session,
    *,
    q: str,
    search_type: SearchType,
    user: User | None,
    page: int,
    per_page: int,
) -> dict:
    _record_search_log(db, q, user, search_type, page)
    if _meili_enabled():
        try:
            return _dispatch(db, q=q, search_type=search_type, user=user, page=page, per_page=per_page, use_meili=True)
        except Exception:
            # 引擎故障不能打断搜索：记日志并回落 SQL 路径（体验回到纯 SQL 水平）
            logger.warning("Meilisearch 查询失败，回落 SQL 搜索: q=%r type=%s", q, search_type, exc_info=True)
    return _dispatch(db, q=q, search_type=search_type, user=user, page=page, per_page=per_page, use_meili=False)


def _meili_suggest(q: str) -> SearchSuggestResponse:
    results = get_query_client().multi_search(
        [
            {
                "indexUid": INDEX_COURSES,
                "q": q,
                "limit": _SUGGEST_COURSE_LIMIT,
                "attributesToRetrieve": ["id", "name", "course_code", "teacher_names", "review_count"],
            },
            {
                "indexUid": INDEX_TEACHERS,
                "q": q,
                "limit": _SUGGEST_TEACHER_LIMIT,
                "attributesToRetrieve": ["id", "name", "title"],
            },
        ]
    )
    courses = [
        SearchSuggestCourse(
            id=hit["id"],
            name=hit.get("name", ""),
            course_code=hit.get("course_code") or None,
            teacher_names=", ".join(hit.get("teacher_names", [])),
            review_count=hit.get("review_count", 0),
        )
        for hit in results[0]["hits"]
    ]
    teachers = [
        SearchSuggestTeacher(id=hit["id"], name=hit.get("name", ""), title=hit.get("title") or None)
        for hit in results[1]["hits"]
    ]
    return SearchSuggestResponse(courses=courses, teachers=teachers)


def _sql_suggest(db: Session, q: str) -> SearchSuggestResponse:
    # 降级实现：前缀匹配（不带前置通配符，能吃索引），体验有损但可用
    pattern = f"{q}%"
    courses = (
        db.query(Course)
        .outerjoin(CourseRate)
        .filter(or_(Course.name.ilike(pattern), Course.course_code.ilike(pattern)))
        .order_by(CourseRate.review_count.desc())
        .limit(_SUGGEST_COURSE_LIMIT)
        .all()
    )
    teachers = db.query(Teacher).filter(Teacher.name.ilike(pattern)).limit(_SUGGEST_TEACHER_LIMIT).all()
    return SearchSuggestResponse(
        courses=[
            SearchSuggestCourse(
                id=course.id,
                name=course.name or "",
                course_code=course.course_code,
                teacher_names=course.teacher_names_display,
                review_count=course.review_count,
            )
            for course in courses
        ],
        teachers=[
            SearchSuggestTeacher(id=teacher.id, name=teacher.name or "", title=teacher.title or None)
            for teacher in teachers
        ],
    )


def search_suggest(db: Session, q: str) -> SearchSuggestResponse:
    """导航栏即时搜索建议：只出课程与教师（公开数据），不记 search_log。"""
    q = q.strip()
    if not q:
        return SearchSuggestResponse()
    if _meili_enabled():
        try:
            return _meili_suggest(q)
        except Exception:
            logger.warning("Meilisearch suggest 失败，回落 SQL 前缀查询: q=%r", q, exc_info=True)
    return _sql_suggest(db, q)
