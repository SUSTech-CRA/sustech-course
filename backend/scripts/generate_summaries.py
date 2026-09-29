#!/usr/bin/env python3
"""离线生成热门课程的公开点评 AI 总结。

默认只读预览；必须显式传 ``--commit`` 才会调用 DeepSeek 并写派生表。

例：先预览并仅测试公开点评不少于 41 条的课程：
    python scripts/generate_summaries.py --min-reviews 41
    python scripts/generate_summaries.py --min-reviews 41 --commit

每日任务使用默认阈值并清掉已跌破阈值的旧派生摘要：
    python scripts/generate_summaries.py --commit --prune-stale
"""

from __future__ import annotations

import argparse
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy.exc import SQLAlchemyError

BACKEND_ROOT = Path(__file__).resolve().parents[1]
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from app.config import settings
from app.core.database import SessionLocal
from app.models import Course, CourseReviewSummary
from app.services.course_summary_service import (
    PROMPT_VERSION,
    DeepSeekSummaryClient,
    SummaryGenerationError,
    build_summary_prompts,
    get_public_review_counts,
    load_public_reviews,
    source_fingerprint,
)


def _log(message: str) -> None:
    print(f"[generate_summaries] {message}", flush=True)


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--min-reviews",
        type=int,
        default=settings.COURSE_SUMMARY_MIN_PUBLIC_REVIEWS,
        help="公开点评最低条数（默认读取 COURSE_SUMMARY_MIN_PUBLIC_REVIEWS）",
    )
    parser.add_argument("--course-id", type=int, action="append", dest="course_ids", help="只处理指定课程，可重复")
    parser.add_argument("--limit", type=int, help="最多生成多少门待更新课程")
    parser.add_argument("--force", action="store_true", help="忽略指纹，强制重新生成")
    parser.add_argument(
        "--prune-stale",
        action="store_true",
        help="删除当前范围内公开点评已跌破阈值的旧摘要（timer 应开启）",
    )
    parser.add_argument("--commit", action="store_true", help="调用 LLM 并写库；不传时仅预览")
    args = parser.parse_args()
    if args.min_reviews < 1:
        parser.error("--min-reviews 必须大于 0")
    if args.limit is not None and args.limit < 1:
        parser.error("--limit 必须大于 0")
    return args


def main() -> int:
    args = _parse_args()
    if args.commit and not settings.LLM_API_KEY:
        _log("LLM_API_KEY 未配置，功能静默关闭，本轮不调用 API、不写库")
        return 0

    started = time.monotonic()
    db = SessionLocal()
    generated = 0
    skipped = 0
    failed = 0
    try:
        counts = get_public_review_counts(
            db,
            min_reviews=args.min_reviews,
            course_ids=args.course_ids,
        )
        scope_query = db.query(CourseReviewSummary)
        if args.course_ids:
            scope_query = scope_query.filter(CourseReviewSummary.course_id.in_(args.course_ids))
        existing_rows = {row.course_id: row for row in scope_query.all()}

        stale_ids = sorted(set(existing_rows) - set(counts))
        if args.prune_stale and stale_ids:
            if args.commit:
                for course_id in stale_ids:
                    db.delete(existing_rows[course_id])
                db.commit()
                _log(f"已删除 {len(stale_ids)} 条低于当前阈值的旧派生摘要")
            else:
                _log(f"预览：{len(stale_ids)} 条旧摘要低于当前阈值，--commit 时会删除")

        course_rows = (
            db.query(Course)
            .filter(Course.id.in_(counts))
            .all()
            if counts
            else []
        )
        courses = sorted(course_rows, key=lambda course: (-counts[course.id], course.id))
        pending: list[tuple[Course, list, str]] = []
        for course in courses:
            reviews = load_public_reviews(db, course.id)
            fingerprint = source_fingerprint(reviews)
            existing = existing_rows.get(course.id)
            unchanged = bool(
                existing
                and existing.source_fingerprint == fingerprint
                and existing.prompt_version == PROMPT_VERSION
                and existing.model == settings.LLM_MODEL
                and existing.source_review_count == len(reviews)
            )
            if unchanged and not args.force:
                skipped += 1
                continue
            pending.append((course, reviews, fingerprint))

        if args.limit is not None:
            pending = pending[: args.limit]
        _log(
            f"阈值 >= {args.min_reviews} 条公开点评：候选 {len(courses)} 门，"
            f"待生成 {len(pending)} 门，指纹未变 {skipped} 门"
        )
        for course, reviews, _fingerprint in pending:
            _log(f"待生成 course={course.id} reviews={len(reviews)} name={course.name}")

        if not args.commit:
            _log("dry-run 结束：未调用 DeepSeek，未写数据库")
            return 0

        with DeepSeekSummaryClient(
            base_url=settings.LLM_BASE_URL,
            api_key=settings.LLM_API_KEY,
            model=settings.LLM_MODEL,
            timeout=settings.LLM_TIMEOUT_SECONDS,
        ) as client:
            for course, reviews, fingerprint in pending:
                try:
                    system_prompt, user_prompt = build_summary_prompts(course, reviews)
                    result = client.generate(system_prompt, user_prompt)
                    row = db.get(CourseReviewSummary, course.id)
                    if row is None:
                        row = CourseReviewSummary(course_id=course.id, is_hidden=False)
                    row.summary_json = result.content.model_dump()
                    row.model = settings.LLM_MODEL
                    row.prompt_version = PROMPT_VERSION
                    row.source_fingerprint = fingerprint
                    row.source_review_count = len(reviews)
                    # 项目数据库统一存无时区 UTC。
                    row.generated_at = datetime.now(UTC).replace(tzinfo=None)
                    row.prompt_tokens = result.usage.prompt_tokens
                    row.completion_tokens = result.usage.completion_tokens
                    row.total_tokens = result.usage.total_tokens
                    row.reasoning_tokens = result.usage.reasoning_tokens
                    db.add(row)
                    db.commit()
                    generated += 1
                    _log(
                        f"已生成 course={course.id} reviews={len(reviews)} "
                        f"tokens={result.usage.total_tokens or 'unknown'}"
                    )
                except (SummaryGenerationError, SQLAlchemyError) as exc:
                    db.rollback()
                    failed += 1
                    _log(f"生成失败 course={course.id}: {exc}")
    except SQLAlchemyError as exc:
        db.rollback()
        _log(
            "数据库操作失败。若尚未建表，请先执行 "
            f"backend/scripts/sql/create_course_review_summary.sql：{exc}"
        )
        return 1
    finally:
        db.close()

    _log(
        f"完成：generated={generated} skipped={skipped} failed={failed} "
        f"耗时={time.monotonic() - started:.1f}s"
    )
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
