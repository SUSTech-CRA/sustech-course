from __future__ import annotations

from datetime import datetime
from html import escape as escape_html
from math import ceil

from fastapi import HTTPException
from sqlalchemy import delete, or_
from sqlalchemy.orm import Session

from app.core.write_audit import record_content_write
from app.models import (
    Course,
    Notification,
    Review,
    ReviewComment,
    ReviewCommentHistory,
    ReviewHistory,
    User,
    follow_course,
    follow_user,
    review_upvotes,
)
from app.schemas.common import PaginatedResponse
from app.schemas.enums import ReviewFeedFilter, ReviewSortBy
from app.schemas.review import CommentCreate, CommentResponse, ReviewCreate, ReviewResponse, ReviewUpdate
from app.services.course_service import serialize_course_brief
from app.services.notification_service import create_notification
from app.utils.parse_at import editor_parse_at
from app.utils.sanitize import sanitize


def can_view_review(review: Review, user: User | None) -> bool:
    if review.is_blocked or review.is_hidden:
        return bool(user and (user.is_admin or review.author_id == user.id))
    if user and user.identity == "Student":
        return True
    if user:
        return not review.only_visible_to_student or review.author_id == user.id
    return not review.only_visible_to_student


def filter_reviews_by_visibility(query, user: User | None, *, feed: bool = False):
    if feed:
        # Public feeds (home "latest reviews" / RSS) hide blocked/hidden reviews for everyone,
        # including their own author and admins, matching the legacy gen_reviews_query().
        query = query.filter(Review.is_blocked.is_(False), Review.is_hidden.is_(False))
    elif user and user.is_admin:
        pass
    elif user:
        query = query.filter(or_(Review.is_blocked.is_(False), Review.author_id == user.id))
        query = query.filter(or_(Review.is_hidden.is_(False), Review.author_id == user.id))
    else:
        query = query.filter(Review.is_blocked.is_(False), Review.is_hidden.is_(False))

    if user and user.identity == "Student":
        return query
    if user:
        return query.filter(or_(Review.only_visible_to_student.is_(False), Review.author_id == user.id))
    return query.filter(Review.only_visible_to_student.is_(False))


def apply_review_order(query, sort_by: ReviewSortBy):
    # pubtime* 按发布时间排序（与老版课程页一致）；updatetime_desc 按更新时间（老版首页最新点评流）。
    if sort_by == ReviewSortBy.UPVOTE:
        return query.order_by(Review.upvote_count.desc(), Review.publish_time.desc())
    if sort_by == ReviewSortBy.PUBTIME_DESC:
        return query.order_by(Review.publish_time.desc())
    if sort_by == ReviewSortBy.PUBTIME:
        return query.order_by(Review.publish_time.asc())
    if sort_by == ReviewSortBy.SCORE_DESC:
        return query.order_by(Review.rate.desc(), Review.publish_time.desc())
    if sort_by == ReviewSortBy.SCORE:
        return query.order_by(Review.rate.asc(), Review.publish_time.desc())
    return query.order_by(Review.update_time.desc())


def _paginate(query, page: int, per_page: int):
    page = max(page, 1)
    per_page = min(max(per_page, 1), 100)
    total = query.count()
    items = query.offset((page - 1) * per_page).limit(per_page).all()
    return items, total, ceil(total / per_page) if total else 0


def serialize_review(review: Review, user: User | None = None) -> ReviewResponse:
    author = None if review.is_anonymous and not (user and (user.is_admin or user.id == review.author_id)) else review.author
    return ReviewResponse(
        id=review.id,
        difficulty=review.difficulty,
        homework=review.homework,
        grading=review.grading,
        gain=review.gain,
        rate=review.rate,
        content=review.content or "",
        publish_time=review.publish_time,
        update_time=review.update_time,
        upvote_count=review.upvote_count or 0,
        comment_count=review.comment_count or 0,
        is_anonymous=bool(review.is_anonymous),
        only_visible_to_student=bool(review.only_visible_to_student),
        is_hidden=bool(review.is_hidden),
        is_blocked=bool(review.is_blocked),
        term=review.term or "",
        author=author,
        course=serialize_course_brief(review.course) if review.course else None,
        difficulty_display=review.difficulty_display,
        homework_display=review.homework_display,
        grading_display=review.grading_display,
        gain_display=review.gain_display,
        term_display=review.term_display,
        is_upvoted=bool(user and user in review.upvote_users),
    )


def get_latest_reviews(
    db: Session,
    *,
    user: User | None,
    page: int,
    per_page: int,
    sort_by: ReviewSortBy = ReviewSortBy.UPDATETIME_DESC,
    feed_filter: ReviewFeedFilter = ReviewFeedFilter.LATEST,
) -> PaginatedResponse[ReviewResponse]:
    query = filter_reviews_by_visibility(db.query(Review), user, feed=True)
    if feed_filter == ReviewFeedFilter.FOLLOWING:
        if not user:
            raise HTTPException(status_code=401, detail="Login required")
        query = query.join(follow_course, Review.course_id == follow_course.c.course_id).filter(follow_course.c.user_id == user.id)
        query = query.filter(Review.author_id != user.id)
    elif feed_filter == ReviewFeedFilter.FOLLOWING_USERS:
        if not user:
            raise HTTPException(status_code=401, detail="Login required")
        # 与老版 follow_reviews?follow_type=user 一致：只看非匿名点评，排除自己
        query = query.filter(Review.is_anonymous.is_(False))
        query = query.join(follow_user, Review.author_id == follow_user.c.followed_id).filter(follow_user.c.follower_id == user.id)
        query = query.filter(Review.author_id != user.id)
    query = apply_review_order(query, sort_by)
    items, total, pages = _paginate(query, page, per_page)
    return PaginatedResponse(items=[serialize_review(item, user) for item in items], total=total, page=page, per_page=per_page, pages=pages)


def get_course_reviews(
    db: Session,
    *,
    course_id: int,
    user: User | None,
    page: int,
    per_page: int,
    sort_by: ReviewSortBy = ReviewSortBy.PUBTIME_DESC,
    term: str | None = None,
    rating: int | None = None,
) -> PaginatedResponse[ReviewResponse]:
    query = filter_reviews_by_visibility(db.query(Review).filter(Review.course_id == course_id), user)
    if term:
        query = query.filter(Review.term == term)
    if rating:
        query = query.filter(Review.rate == rating)
    query = apply_review_order(query, sort_by)
    items, total, pages = _paginate(query, page, per_page)
    return PaginatedResponse(items=[serialize_review(item, user) for item in items], total=total, page=page, per_page=per_page, pages=pages)


def get_public_feed_reviews(db: Session, limit: int = 100) -> list[Review]:
    query = filter_reviews_by_visibility(db.query(Review), None, feed=True)
    return query.order_by(Review.update_time.desc()).limit(limit).all()


def get_review_detail(db: Session, review_id: int, user: User | None) -> ReviewResponse:
    review = db.get(Review, review_id)
    if not review:
        raise HTTPException(status_code=404, detail="Review not found")
    if not can_view_review(review, user):
        raise HTTPException(status_code=404, detail="Review not found")
    return serialize_review(review, user)


def _record_review_history(db: Session, review: Review, operation_user: User, operation: str) -> None:
    db.add(
        ReviewHistory(
            difficulty=review.difficulty,
            homework=review.homework,
            grading=review.grading,
            gain=review.gain,
            rate=review.rate,
            content=review.content,
            publish_time=review.publish_time,
            update_time=review.update_time,
            author_id=review.author_id,
            course_id=review.course_id,
            term=review.term,
            is_anonymous=review.is_anonymous,
            only_visible_to_student=review.only_visible_to_student,
            is_hidden=review.is_hidden,
            is_blocked=review.is_blocked,
            review_id=review.id,
            operation_user_id=operation_user.id,
            operation=operation,
        )
    )


def _review_notify_recipients(review: Review, author: User) -> set[User]:
    """与老版 new_review 一致：通知课程关注者，非匿名时再加作者粉丝，排除作者本人。"""
    recipients: set[User] = set(review.course.followers) if review.course else set()
    if not review.is_anonymous:
        recipients.update(author.followers)
    recipients.discard(author)
    return recipients


def create_review(db: Session, payload: ReviewCreate, author: User) -> ReviewResponse:
    course = db.get(Course, payload.course_id)
    if not course:
        raise HTTPException(status_code=404, detail="Course not found")
    if payload.term not in course.term_ids:
        raise HTTPException(status_code=422, detail="无效的开课学期")
    # 同一课程的点评聚合与“每人每课一评”检查共用 course_rates 行锁串行化。
    course.lock_course_rate(db)
    exists = (
        db.query(Review.id)
        .filter(Review.course_id == payload.course_id, Review.author_id == author.id)
        .with_for_update()
        .first()
    )
    if exists:
        raise HTTPException(status_code=409, detail="Each user can only add one review for each course")
    data = payload.model_dump()
    linked_content, mentioned_users = editor_parse_at(db, data["content"])
    data["content"] = sanitize(linked_content)
    review = Review(author=author, course=course, **data)
    db.add(review)
    db.flush()
    if course not in author.reviewed_course:
        author.reviewed_course.append(course)
    _record_review_history(db, review, author, "create")
    course.update_rate(db, commit_db=False)
    if not review.is_hidden and not review.is_blocked:
        for follower in _review_notify_recipients(review, author):
            create_notification(
                db, to_user=follower, from_user=author, operation="review", ref_obj=review, ref_display_class="Course", commit=False
            )
        for mentioned in mentioned_users:
            create_notification(db, to_user=mentioned, from_user=author, operation="mention", ref_obj=review, commit=False)
    db.commit()
    db.refresh(review)
    record_content_write(
        action="review.create",
        user_id=author.id,
        object_type="review",
        object_id=review.id,
        meta={"course_id": review.course_id},
    )
    return serialize_review(review, author)


def update_review(db: Session, review_id: int, payload: ReviewUpdate, user: User) -> ReviewResponse:
    review = db.get(Review, review_id)
    if not review:
        raise HTTPException(status_code=404, detail="Review not found")
    if review.author_id != user.id and not user.is_admin:
        raise HTTPException(status_code=403, detail="Not allowed")
    data = payload.model_dump(exclude_unset=True)
    if "term" in data and data["term"] != review.term and data["term"] not in review.course.term_ids:
        raise HTTPException(status_code=422, detail="无效的开课学期")
    mentioned_users: set[User] = set()
    if data.get("content") is not None:
        linked_content, mentioned_users = editor_parse_at(db, data["content"])
        data["content"] = sanitize(linked_content)

    review.course.lock_course_rate(db)
    old_values = {field: getattr(review, field) for field in ("content", "difficulty", "homework", "grading", "gain", "rate")}
    for key, value in data.items():
        setattr(review, key, value)
    # 与老版一致：仅在内容/评分实际变化时刷新 update_time 并通知；只改隐私设置不顶到最新点评流
    content_changed = any(getattr(review, field) != value for field, value in old_values.items())
    if content_changed:
        review.update_time = datetime.utcnow()

    _record_review_history(db, review, user, "update")
    review.course.update_rate(db, commit_db=False)
    if content_changed and not review.is_hidden and not review.is_blocked:
        author = review.author or user
        for follower in _review_notify_recipients(review, author):
            if follower.id == user.id:
                continue
            create_notification(
                db, to_user=follower, from_user=author, operation="update-review", ref_obj=review, ref_display_class="Course", commit=False
            )
        for mentioned in mentioned_users:
            create_notification(db, to_user=mentioned, from_user=author, operation="mention", ref_obj=review, commit=False)
    db.commit()
    db.refresh(review)
    record_content_write(
        action="review.update",
        user_id=user.id,
        object_type="review",
        object_id=review.id,
        meta={"course_id": review.course_id},
    )
    return serialize_review(review, user)


def delete_review(db: Session, review_id: int, user: User) -> None:
    review = db.get(Review, review_id)
    if not review:
        raise HTTPException(status_code=404, detail="Review not found")
    if review.author_id != user.id and not user.is_admin:
        raise HTTPException(status_code=403, detail="Not allowed")
    course = review.course
    author = review.author
    course.lock_course_rate(db)
    _record_review_history(db, review, user, "delete")
    for comment in list(review.comments):
        db.add(
            ReviewCommentHistory(
                review_id=comment.review_id,
                author_id=comment.author_id,
                content=comment.content,
                publish_time=comment.publish_time,
                comment_id=comment.id,
                operation_user_id=user.id,
                operation="delete",
            )
        )
        db.delete(comment)
    review.upvote_users.clear()
    if course in author.reviewed_course:
        author.reviewed_course.remove(course)
    db.delete(review)
    db.flush()
    course.update_rate(db, commit_db=False)
    db.commit()


def toggle_review_upvote(db: Session, review_id: int, user: User, enabled: bool) -> ReviewResponse:
    locked_review_id = db.query(Review.id).filter(Review.id == review_id).with_for_update().scalar()
    review = db.get(Review, locked_review_id) if locked_review_id is not None else None
    if not review or not can_view_review(review, user):
        raise HTTPException(status_code=404, detail="Review not found")
    existing = bool(
        db.query(review_upvotes.c.author_id)
        .filter(review_upvotes.c.review_id == review.id, review_upvotes.c.author_id == user.id)
        .with_for_update()
        .first()
    )
    if enabled and not existing:
        db.execute(review_upvotes.insert().values(review_id=review.id, author_id=user.id))
        if review.author and review.author_id != user.id:
            create_notification(db, to_user=review.author, from_user=user, operation="upvote", ref_obj=review, commit=False)
    if not enabled and existing:
        db.execute(
            delete(review_upvotes).where(
                review_upvotes.c.review_id == review.id,
                review_upvotes.c.author_id == user.id,
            )
        )
        # 与老版一致：取消点赞时撤回点赞通知
        db.query(Notification).filter(
            Notification.from_user_id == user.id,
            Notification.to_user_id == review.author_id,
            Notification.operation == "upvote",
            Notification.ref_class == "Review",
            Notification.ref_obj_id == review.id,
        ).delete(synchronize_session=False)
    db.flush()
    review.upvote_count = len(
        {
            author_id
            for (author_id,) in db.query(review_upvotes.c.author_id)
            .filter(review_upvotes.c.review_id == review.id)
            .with_for_update()
            .all()
        }
    )
    db.commit()
    return serialize_review(review, user)


def set_review_blocked(db: Session, review_id: int, user: User, blocked: bool) -> ReviewResponse:
    review = db.get(Review, review_id)
    if not review:
        raise HTTPException(status_code=404, detail="Review not found")
    review.course.lock_course_rate(db)
    review.is_blocked = blocked
    _record_review_history(db, review, user, "block" if blocked else "unblock")
    review.course.update_rate(db, commit_db=False)
    db.commit()
    return serialize_review(review, user)


def set_review_hidden(db: Session, review_id: int, user: User, hidden: bool) -> ReviewResponse:
    review = db.get(Review, review_id)
    if not review:
        raise HTTPException(status_code=404, detail="Review not found")
    if review.author_id != user.id and not user.is_admin:
        raise HTTPException(status_code=403, detail="Not allowed")
    review.course.lock_course_rate(db)
    review.is_hidden = hidden
    _record_review_history(db, review, user, "hide" if hidden else "unhide")
    review.course.update_rate(db, commit_db=False)
    db.commit()
    return serialize_review(review, user)


def get_comments(db: Session, review_id: int, user: User | None) -> list[CommentResponse]:
    review = db.get(Review, review_id)
    if not review or not can_view_review(review, user):
        raise HTTPException(status_code=404, detail="Review not found")
    return [CommentResponse.model_validate(comment) for comment in review.comments]


def add_comment(db: Session, review_id: int, payload: CommentCreate, user: User) -> CommentResponse:
    locked_review_id = db.query(Review.id).filter(Review.id == review_id).with_for_update().scalar()
    review = db.get(Review, locked_review_id) if locked_review_id is not None else None
    if not review or not can_view_review(review, user):
        raise HTTPException(status_code=404, detail="Review not found")
    linked_content, mentioned_users = editor_parse_at(db, escape_html(payload.content))
    comment = ReviewComment(review=review, author=user, content=linked_content)
    db.add(comment)
    db.flush()
    db.add(
        ReviewCommentHistory(
            review_id=comment.review_id,
            author_id=comment.author_id,
            content=comment.content,
            publish_time=comment.publish_time,
            comment_id=comment.id,
            operation_user_id=user.id,
            operation="create",
        )
    )
    review.comment_count = len(
        {
            comment_id
            for (comment_id,) in db.query(ReviewComment.id)
            .filter(ReviewComment.review_id == review.id)
            .with_for_update()
            .all()
        }
    )
    if review.author and review.author_id != user.id:
        create_notification(db, to_user=review.author, from_user=user, operation="comment", ref_obj=comment, commit=False)
    for mentioned in mentioned_users:
        create_notification(db, to_user=mentioned, from_user=user, operation="mention", ref_obj=comment, commit=False)
    db.commit()
    db.refresh(comment)
    record_content_write(
        action="comment.create",
        user_id=user.id,
        object_type="comment",
        object_id=comment.id,
        meta={"review_id": comment.review_id},
    )
    return CommentResponse.model_validate(comment)


def delete_comment(db: Session, comment_id: int, user: User) -> None:
    review_id = db.query(ReviewComment.review_id).filter(ReviewComment.id == comment_id).scalar()
    if review_id is None:
        raise HTTPException(status_code=404, detail="Comment not found")
    locked_review_id = db.query(Review.id).filter(Review.id == review_id).with_for_update().scalar()
    review = db.get(Review, locked_review_id) if locked_review_id is not None else None
    comment = db.query(ReviewComment).filter(ReviewComment.id == comment_id).with_for_update().one_or_none()
    if review is None or comment is None:
        raise HTTPException(status_code=404, detail="Comment not found")
    if comment.author_id != user.id and not user.is_admin:
        raise HTTPException(status_code=403, detail="Not allowed")
    db.add(
        ReviewCommentHistory(
            review_id=comment.review_id,
            author_id=comment.author_id,
            content=comment.content,
            publish_time=comment.publish_time,
            comment_id=comment.id,
            operation_user_id=user.id,
            operation="delete",
        )
    )
    db.delete(comment)
    db.flush()
    review.comment_count = len(
        {
            remaining_id
            for (remaining_id,) in db.query(ReviewComment.id)
            .filter(ReviewComment.review_id == review.id)
            .with_for_update()
            .all()
        }
    )
    db.commit()
