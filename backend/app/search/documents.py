"""搜索索引的文档构建与索引配置。

三个索引均为 MySQL 的只读派生数据，由 backend/scripts/reindex_search.py
定时全量重建（staging + swap-indexes 原子切换），随时可丢弃重建。

红线（勿破坏）：
- reviews 索引不存任何作者字段——匿名点评不可能经由索引去匿名化；
  按作者名搜点评在 search_service 里用 DB 精确查询补齐。
- 只索引未屏蔽/未隐藏的点评（与老应用搜索行为一致：搜索对所有人
  不返回 blocked/hidden）；only_visible_to_student 进索引作查询期过滤，
  保证分页每页条数精确。命中 ID 回 MySQL hydrate 时仍会再过一遍
  filter_reviews_by_visibility 兜底（防索引滞后窗口）。
"""

from __future__ import annotations

import calendar
import re
from typing import Any

import lxml.html
from sqlalchemy.orm import Session

from app.models import Course, CourseRate, CourseTerm, Review, Teacher

INDEX_COURSES = "courses"
INDEX_REVIEWS = "reviews"
INDEX_TEACHERS = "teachers"

# 高亮哨兵：私有区字符，真实内容中不会出现。查询侧先 HTML 转义
# 再把哨兵替换成 <mark>，保证 snippet 无 XSS 面。
HIGHLIGHT_PRE = "\ue000"
HIGHLIGHT_POST = "\ue001"

# Meilisearch 默认 rankingRules（words/typo/proximity/attribute/sort/exactness）
_DEFAULT_RANKING = ["words", "typo", "proximity", "attribute", "sort", "exactness"]

INDEX_SETTINGS: dict[str, dict[str, Any]] = {
    # searchableAttributes 的顺序即 attribute 规则的字段权重：课名 > 课号 > 历史课号 > 教师名。
    # 相关性同分时按热度（点评数、均分）排序，修掉纯 SQL 版“只按热度排”的问题。
    INDEX_COURSES: {
        "searchableAttributes": ["name", "course_code", "courseries", "teacher_names"],
        "filterableAttributes": [],
        "sortableAttributes": [],
        "rankingRules": [*_DEFAULT_RANKING, "review_count:desc", "rate_average:desc"],
    },
    INDEX_REVIEWS: {
        "searchableAttributes": ["content", "course_name", "course_code", "teacher_names"],
        "filterableAttributes": ["only_visible_to_student"],
        "sortableAttributes": ["update_time"],
        "rankingRules": [*_DEFAULT_RANKING, "update_time:desc"],
    },
    INDEX_TEACHERS: {
        "searchableAttributes": ["name", "email", "title", "research_interest"],
        "filterableAttributes": [],
        "sortableAttributes": [],
        "rankingRules": _DEFAULT_RANKING,
    },
}


def html_to_text(html: str | None) -> str:
    """HTML → 纯文本，用于索引与摘要。

    lxml text_content 直接拼接文本节点，行内标签不会截断词
    （``<b>很</b>好`` → ``很好``，LIKE 版搜不到的场景在索引里能命中）。
    """
    if not html or not html.strip():
        return ""
    try:
        text = lxml.html.fromstring(html).text_content()
    except lxml.etree.ParserError:
        text = re.sub(r"<[^>]+>", " ", html)
    return " ".join(text.split())


def _utc_epoch(dt) -> int:
    # 库里的 DateTime 是无时区的 UTC；按 UTC 转 epoch 供 update_time:desc 排序
    return calendar.timegm(dt.utctimetuple()) if dt else 0


def build_course_documents(db: Session) -> list[dict[str, Any]]:
    courseries_map: dict[int, set[str]] = {}
    for course_id, courseries in (
        db.query(CourseTerm.course_id, CourseTerm.courseries).filter(CourseTerm.courseries.isnot(None)).distinct()
    ):
        if courseries:
            courseries_map.setdefault(course_id, set()).add(courseries)

    # 直接读 CourseRate 表；不要走 Course.course_rate property——
    # 它对缺行课程会在 session 里挂一个待插入的 CourseRate（本模块必须对 MySQL 零写入）
    rate_map = {rate.id: rate for rate in db.query(CourseRate).all()}

    documents = []
    for course in db.query(Course).all():
        rate = rate_map.get(course.id)
        documents.append(
            {
                "id": course.id,
                "name": course.name or "",
                "course_code": course.course_code or "",
                "courseries": sorted(courseries_map.get(course.id, ())),
                "teacher_names": course.teacher_name_list,
                "review_count": (rate.review_count or 0) if rate else 0,
                "rate_average": (rate._rate_average or 0.0) if rate else 0.0,
            }
        )
    return documents


def build_review_documents(db: Session, course_docs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    course_map = {doc["id"]: doc for doc in course_docs}
    # 只取需要的列：Review 的 course/author/comments 关系都是 joined loading，
    # 整对象查询会把全站评论一起载入
    rows = (
        db.query(Review.id, Review.content, Review.only_visible_to_student, Review.update_time, Review.course_id)
        .filter(Review.is_hidden.is_(False), Review.is_blocked.is_(False))
        .all()
    )
    documents = []
    for row in rows:
        course_doc = course_map.get(row.course_id, {})
        documents.append(
            {
                "id": row.id,
                "content": html_to_text(row.content),
                "course_name": course_doc.get("name", ""),
                "course_code": course_doc.get("course_code", ""),
                "teacher_names": course_doc.get("teacher_names", []),
                "only_visible_to_student": bool(row.only_visible_to_student),
                "update_time": _utc_epoch(row.update_time),
            }
        )
    return documents


def build_teacher_documents(db: Session) -> list[dict[str, Any]]:
    rows = db.query(Teacher.id, Teacher.name, Teacher.email, Teacher.title, Teacher.research_interest).all()
    return [
        {
            "id": row.id,
            "name": row.name or "",
            "email": row.email or "",
            "title": row.title or "",
            "research_interest": html_to_text(row.research_interest),
        }
        for row in rows
    ]


def build_all_documents(db: Session) -> dict[str, list[dict[str, Any]]]:
    course_docs = build_course_documents(db)
    return {
        INDEX_COURSES: course_docs,
        INDEX_REVIEWS: build_review_documents(db, course_docs),
        INDEX_TEACHERS: build_teacher_documents(db),
    }
