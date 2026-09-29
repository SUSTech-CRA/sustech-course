#!/usr/bin/env python3
"""审计并修复点评相关的冗余聚合与计数。

覆盖范围：

* ``course_rates`` 的可见点评数量、五项评分总数和平均分；
* ``reviews`` 的评论数、点赞数；
* ``course_rates`` 的课程点赞、点踩、关注、加入人数；
* ``users`` 的关注数、粉丝数；
* 缺少唯一键的 ``follow_user`` / ``upvote_course`` /
  ``downvote_course`` / ``review_course`` 中完全重复的关联 pair。

脚本默认只读。生产建议在低写入时段按以下顺序执行；先部署并重启包含
新写路径的应用，避免回填后又被旧代码写坏：

1. ``python scripts/repair_course_rates.py``（审计并保存输出）
2. ``python scripts/repair_course_rates.py --commit``（单事务去重并回填）
3. ``python scripts/repair_course_rates.py``（确认所有差异均为 0）
4. ``python scripts/reindex_search.py``（课程评分变化后重建搜索索引）

``--course-id`` 可重复传入，只限定课程、课程点评及课程关系计数；用户关注
计数和重复 ``follow_user`` 仍会全量审计，以免留下彼此关联的半修复状态。
访问量和未读通知数没有可用于历史回填的事实表，因此不在脚本修复范围内；
新代码已经把它们改为数据库原子更新，防止后续并发覆盖。
"""

from __future__ import annotations

import argparse
import math
import sys
from dataclasses import dataclass
from pathlib import Path

from sqlalchemy import delete, func
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

BACKEND_ROOT = Path(__file__).resolve().parents[1]
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from app.core.database import SessionLocal
from app.models import (
    Course,
    CourseClass,
    CourseRate,
    Review,
    ReviewComment,
    User,
    downvote_course,
    follow_course,
    follow_user,
    join_course,
    review_course,
    review_upvotes,
    upvote_course,
)


@dataclass(frozen=True)
class CourseRateAggregate:
    review_count: int
    difficulty_total: int
    homework_total: int
    grading_total: int
    gain_total: int
    rate_total: int
    rate_average: float | None


@dataclass(frozen=True)
class CourseRateMismatch:
    course_id: int
    stored: CourseRateAggregate | None
    expected: CourseRateAggregate


@dataclass(frozen=True)
class CountMismatch:
    entity: str
    entity_id: int
    field: str
    stored: int | None
    expected: int


@dataclass(frozen=True)
class RelationDuplicate:
    table: str
    left_field: str
    left_id: int
    right_field: str
    right_id: int
    rows: int


@dataclass(frozen=True)
class _RelationSpec:
    table: object
    left_field: str
    right_field: str


_DUPLICATE_RELATIONS = {
    spec.table.name: spec
    for spec in (
        _RelationSpec(follow_user, "follower_id", "followed_id"),
        _RelationSpec(upvote_course, "user_id", "course_id"),
        _RelationSpec(downvote_course, "user_id", "course_id"),
        _RelationSpec(review_course, "user_id", "course_id"),
    )
}


def _log(message: str) -> None:
    print(f"[repair_course_rates] {message}", flush=True)


def _aggregate(
    *,
    review_count: int | None,
    difficulty_total: int | None,
    homework_total: int | None,
    grading_total: int | None,
    gain_total: int | None,
    rate_total: int | None,
) -> CourseRateAggregate:
    count = int(review_count or 0)
    total = int(rate_total or 0)
    return CourseRateAggregate(
        review_count=count,
        difficulty_total=int(difficulty_total or 0),
        homework_total=int(homework_total or 0),
        grading_total=int(grading_total or 0),
        gain_total=int(gain_total or 0),
        rate_total=total,
        rate_average=(total / count) if count else None,
    )


def _stored_aggregate(row: CourseRate) -> CourseRateAggregate:
    return CourseRateAggregate(
        review_count=int(row.review_count or 0),
        difficulty_total=int(row._difficulty_total or 0),
        homework_total=int(row._homework_total or 0),
        grading_total=int(row._grading_total or 0),
        gain_total=int(row._gain_total or 0),
        rate_total=int(row._rate_total or 0),
        rate_average=float(row._rate_average) if row._rate_average is not None else None,
    )


def _aggregates_match(stored: CourseRateAggregate, expected: CourseRateAggregate) -> bool:
    totals_match = (
        stored.review_count == expected.review_count
        and stored.difficulty_total == expected.difficulty_total
        and stored.homework_total == expected.homework_total
        and stored.grading_total == expected.grading_total
        and stored.gain_total == expected.gain_total
        and stored.rate_total == expected.rate_total
    )
    if not totals_match:
        return False
    # 存量无点评课程中同时存在 0.0 和 NULL；两者对 API 都表示无评分，
    # 本脚本不为这项历史表示差异扩大生产写入范围。
    if expected.review_count == 0:
        return True
    if stored.rate_average is None or expected.rate_average is None:
        return stored.rate_average is expected.rate_average
    # 生产列是单精度 FLOAT，允许其正常的十进制舍入误差。
    return math.isclose(stored.rate_average, expected.rate_average, rel_tol=1e-5, abs_tol=1e-5)


def find_course_rate_mismatches(
    db: Session,
    *,
    course_ids: list[int] | None = None,
) -> list[CourseRateMismatch]:
    review_query = db.query(
        Review.course_id,
        func.count(Review.id),
        func.sum(Review.difficulty),
        func.sum(Review.homework),
        func.sum(Review.grading),
        func.sum(Review.gain),
        func.sum(Review.rate),
    ).filter(Review.is_hidden.is_(False), Review.is_blocked.is_(False))
    rate_query = db.query(CourseRate)
    if course_ids:
        review_query = review_query.filter(Review.course_id.in_(course_ids))
        rate_query = rate_query.filter(CourseRate.id.in_(course_ids))

    expected_by_id = {
        int(row[0]): _aggregate(
            review_count=row[1],
            difficulty_total=row[2],
            homework_total=row[3],
            grading_total=row[4],
            gain_total=row[5],
            rate_total=row[6],
        )
        for row in review_query.group_by(Review.course_id).all()
    }
    stored_rows = {int(rate.id): rate for rate in rate_query.all()}

    # 不为“无点评且从来没有 course_rates 行”的课程补行，避免改变旧站内连接语义。
    scoped_ids = sorted(set(expected_by_id) | set(stored_rows))
    mismatches: list[CourseRateMismatch] = []
    empty = _aggregate(
        review_count=0,
        difficulty_total=0,
        homework_total=0,
        grading_total=0,
        gain_total=0,
        rate_total=0,
    )
    for course_id in scoped_ids:
        expected = expected_by_id.get(course_id, empty)
        row = stored_rows.get(course_id)
        stored = _stored_aggregate(row) if row else None
        if stored is None or not _aggregates_match(stored, expected):
            mismatches.append(CourseRateMismatch(course_id=course_id, stored=stored, expected=expected))
    return mismatches


def _grouped_counts(query, key_column) -> dict[int, int]:
    return {int(key): int(count) for key, count in query.group_by(key_column).all()}


def find_count_mismatches(
    db: Session,
    *,
    course_ids: list[int] | None = None,
) -> list[CountMismatch]:
    mismatches: list[CountMismatch] = []

    review_query = db.query(Review.id, Review.comment_count, Review.upvote_count)
    comment_query = db.query(ReviewComment.review_id, func.count(ReviewComment.id)).join(
        Review, Review.id == ReviewComment.review_id
    )
    review_upvote_query = db.query(
        review_upvotes.c.review_id,
        func.count(func.distinct(review_upvotes.c.author_id)),
    ).join(Review, Review.id == review_upvotes.c.review_id)
    if course_ids:
        review_query = review_query.filter(Review.course_id.in_(course_ids))
        comment_query = comment_query.filter(Review.course_id.in_(course_ids))
        review_upvote_query = review_upvote_query.filter(Review.course_id.in_(course_ids))
    comments_by_review = _grouped_counts(comment_query, ReviewComment.review_id)
    upvotes_by_review = _grouped_counts(review_upvote_query, review_upvotes.c.review_id)
    for review_id, stored_comments, stored_upvotes in review_query.all():
        for field, stored, expected in (
            ("comment_count", stored_comments, comments_by_review.get(int(review_id), 0)),
            ("upvote_count", stored_upvotes, upvotes_by_review.get(int(review_id), 0)),
        ):
            normalized_stored = int(stored or 0)
            if normalized_stored != expected:
                mismatches.append(CountMismatch("review", int(review_id), field, normalized_stored, expected))

    rate_query = db.query(
        CourseRate.id,
        CourseRate.upvote_count,
        CourseRate.downvote_count,
        CourseRate.follow_count,
        CourseRate.join_count,
    )
    course_upvote_query = db.query(
        upvote_course.c.course_id,
        func.count(func.distinct(upvote_course.c.user_id)),
    )
    course_downvote_query = db.query(
        downvote_course.c.course_id,
        func.count(func.distinct(downvote_course.c.user_id)),
    )
    course_follow_query = db.query(
        follow_course.c.course_id,
        func.count(func.distinct(follow_course.c.user_id)),
    )
    course_join_query = db.query(
        CourseClass.course_id,
        func.count(func.distinct(join_course.c.student_id)),
    ).join(join_course, join_course.c.class_id == CourseClass.id)
    if course_ids:
        rate_query = rate_query.filter(CourseRate.id.in_(course_ids))
        course_upvote_query = course_upvote_query.filter(upvote_course.c.course_id.in_(course_ids))
        course_downvote_query = course_downvote_query.filter(downvote_course.c.course_id.in_(course_ids))
        course_follow_query = course_follow_query.filter(follow_course.c.course_id.in_(course_ids))
        course_join_query = course_join_query.filter(CourseClass.course_id.in_(course_ids))
    upvotes_by_course = _grouped_counts(course_upvote_query, upvote_course.c.course_id)
    downvotes_by_course = _grouped_counts(course_downvote_query, downvote_course.c.course_id)
    follows_by_course = _grouped_counts(course_follow_query, follow_course.c.course_id)
    joins_by_course = _grouped_counts(course_join_query, CourseClass.course_id)
    stored_rates = {
        int(row.id): {
            "upvote_count": int(row.upvote_count or 0),
            "downvote_count": int(row.downvote_count or 0),
            "follow_count": int(row.follow_count or 0),
            "join_count": int(row.join_count or 0),
        }
        for row in rate_query.all()
    }
    expected_course_counts = {
        "upvote_count": upvotes_by_course,
        "downvote_count": downvotes_by_course,
        "follow_count": follows_by_course,
        "join_count": joins_by_course,
    }
    course_scope = set(stored_rates)
    for values in expected_course_counts.values():
        course_scope.update(values)
    for course_id in sorted(course_scope):
        stored = stored_rates.get(course_id)
        for field, expected_values in expected_course_counts.items():
            expected = expected_values.get(course_id, 0)
            stored_value = stored[field] if stored is not None else None
            if stored_value != expected:
                mismatches.append(CountMismatch("course_rate", course_id, field, stored_value, expected))

    following_by_user = _grouped_counts(
        db.query(follow_user.c.follower_id, func.count(func.distinct(follow_user.c.followed_id))),
        follow_user.c.follower_id,
    )
    followers_by_user = _grouped_counts(
        db.query(follow_user.c.followed_id, func.count(func.distinct(follow_user.c.follower_id))),
        follow_user.c.followed_id,
    )
    for user_id, stored_following, stored_followers in db.query(
        User.id, User.following_count, User.follower_count
    ).all():
        for field, stored, expected in (
            ("following_count", stored_following, following_by_user.get(int(user_id), 0)),
            ("follower_count", stored_followers, followers_by_user.get(int(user_id), 0)),
        ):
            normalized_stored = int(stored or 0)
            if normalized_stored != expected:
                mismatches.append(CountMismatch("user", int(user_id), field, normalized_stored, expected))

    return mismatches


def find_relation_duplicates(
    db: Session,
    *,
    course_ids: list[int] | None = None,
) -> list[RelationDuplicate]:
    duplicates: list[RelationDuplicate] = []
    for spec in _DUPLICATE_RELATIONS.values():
        left = spec.table.c[spec.left_field]
        right = spec.table.c[spec.right_field]
        query = db.query(left, right, func.count().label("rows"))
        if course_ids and spec.table.name != follow_user.name:
            query = query.filter(spec.table.c.course_id.in_(course_ids))
        rows = query.group_by(left, right).having(func.count() > 1).all()
        duplicates.extend(
            RelationDuplicate(
                table=spec.table.name,
                left_field=spec.left_field,
                left_id=int(left_id),
                right_field=spec.right_field,
                right_id=int(right_id),
                rows=int(row_count),
            )
            for left_id, right_id, row_count in rows
        )
    return sorted(duplicates, key=lambda row: (row.table, row.left_id, row.right_id))


def repair_relation_duplicates(
    db: Session,
    duplicates: list[RelationDuplicate],
    *,
    commit_db: bool = True,
) -> None:
    for duplicate in duplicates:
        spec = _DUPLICATE_RELATIONS[duplicate.table]
        condition = (
            (spec.table.c[spec.left_field] == duplicate.left_id)
            & (spec.table.c[spec.right_field] == duplicate.right_id)
        )
        db.execute(delete(spec.table).where(condition))
        db.execute(
            spec.table.insert().values(
                {
                    spec.left_field: duplicate.left_id,
                    spec.right_field: duplicate.right_id,
                }
            )
        )
    if commit_db:
        db.commit()


def repair_course_rates(
    db: Session,
    mismatches: list[CourseRateMismatch],
    *,
    commit_db: bool = True,
) -> None:
    for mismatch in mismatches:
        course = db.get(Course, mismatch.course_id)
        if course is None:
            raise RuntimeError(f"course {mismatch.course_id} does not exist")
        course.update_rate(db, commit_db=False)
    if commit_db:
        db.commit()


def repair_count_mismatches(
    db: Session,
    mismatches: list[CountMismatch],
    *,
    commit_db: bool = True,
) -> None:
    for mismatch in mismatches:
        if mismatch.entity == "review":
            entity = db.get(Review, mismatch.entity_id)
        elif mismatch.entity == "user":
            entity = db.get(User, mismatch.entity_id)
        elif mismatch.entity == "course_rate":
            entity = db.get(CourseRate, mismatch.entity_id)
            if entity is None:
                course = db.get(Course, mismatch.entity_id)
                if course is None:
                    raise RuntimeError(f"course {mismatch.entity_id} does not exist")
                entity = course.ensure_course_rate(db)
        else:
            raise RuntimeError(f"unknown entity type: {mismatch.entity}")
        if entity is None:
            raise RuntimeError(f"{mismatch.entity} {mismatch.entity_id} does not exist")
        setattr(entity, mismatch.field, mismatch.expected)
    if commit_db:
        db.commit()


def _format_rate(aggregate: CourseRateAggregate | None) -> str:
    if aggregate is None:
        return "missing"
    return (
        f"count={aggregate.review_count} rate={aggregate.rate_total} "
        f"difficulty={aggregate.difficulty_total} homework={aggregate.homework_total} "
        f"grading={aggregate.grading_total} gain={aggregate.gain_total} "
        f"average={aggregate.rate_average}"
    )


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--course-id", type=int, action="append", dest="course_ids", help="只处理指定课程，可重复")
    parser.add_argument("--commit", action="store_true", help="写回修复；不传时只读审计")
    parser.add_argument("--details-limit", type=int, default=100, help="每类最多打印多少条差异详情，默认 100")
    args = parser.parse_args()
    if args.details_limit < 0:
        parser.error("--details-limit 不能小于 0")
    return args


def _audit(db: Session, course_ids: list[int] | None):
    duplicates = find_relation_duplicates(db, course_ids=course_ids)
    rates = find_course_rate_mismatches(db, course_ids=course_ids)
    counts = find_count_mismatches(db, course_ids=course_ids)
    return duplicates, rates, counts


def main() -> int:
    args = _parse_args()
    db = SessionLocal()
    try:
        duplicates, rate_mismatches, count_mismatches = _audit(db, args.course_ids)
        _log(
            f"发现重复关联 {len(duplicates)} 组、课程点评聚合差异 {len(rate_mismatches)} 门、"
            f"冗余计数差异 {len(count_mismatches)} 项"
        )
        for duplicate in duplicates[: args.details_limit]:
            _log(
                f"duplicate {duplicate.table} "
                f"{duplicate.left_field}={duplicate.left_id} "
                f"{duplicate.right_field}={duplicate.right_id} rows={duplicate.rows}"
            )
        for mismatch in rate_mismatches[: args.details_limit]:
            _log(
                f"course={mismatch.course_id} stored[{_format_rate(mismatch.stored)}] "
                f"expected[{_format_rate(mismatch.expected)}]"
            )
        for mismatch in count_mismatches[: args.details_limit]:
            _log(
                f"{mismatch.entity}={mismatch.entity_id} field={mismatch.field} "
                f"stored={mismatch.stored} expected={mismatch.expected}"
            )

        if not args.commit:
            db.rollback()
            _log("dry-run 结束，未写数据库；传 --commit 才会修复")
            return 0
        if not duplicates and not rate_mismatches and not count_mismatches:
            db.rollback()
            _log("无需修复")
            return 0

        # 顺序很重要：先去重事实关系，再修评分聚合，最后按去重后的事实回填计数。
        repair_relation_duplicates(db, duplicates, commit_db=False)
        repair_course_rates(db, rate_mismatches, commit_db=False)
        db.flush()
        refreshed_counts = find_count_mismatches(db, course_ids=args.course_ids)
        repair_count_mismatches(db, refreshed_counts, commit_db=False)
        db.flush()

        remaining = _audit(db, args.course_ids)
        if any(remaining):
            db.rollback()
            _log(
                f"写回验证失败，事务已回滚：重复关联 {len(remaining[0])} 组、"
                f"点评聚合 {len(remaining[1])} 门、计数 {len(remaining[2])} 项"
            )
            return 1
        db.commit()
        _log(
            f"已去重 {len(duplicates)} 组关联、修复 {len(rate_mismatches)} 门课程点评聚合、"
            f"回填 {len(refreshed_counts)} 项计数；请再次 dry-run 并重建 Meilisearch 课程索引"
        )
        return 0
    except (RuntimeError, SQLAlchemyError) as exc:
        db.rollback()
        _log(f"失败，事务已回滚：{exc}")
        return 1
    finally:
        db.close()


if __name__ == "__main__":
    sys.exit(main())
