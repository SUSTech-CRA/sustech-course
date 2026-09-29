from __future__ import annotations

from datetime import datetime
from html import escape
from math import ceil

from fastapi import HTTPException
from sqlalchemy import func, update
from sqlalchemy.orm import Session

from app.models import Course, Notification, Review, ReviewComment, Teacher, User
from app.schemas.common import PaginatedResponse
from app.schemas.user import NotificationResponse


def _link(path: str, text: str | None) -> str:
    return f'<a href="{escape(path, quote=True)}">{escape(text or "")}</a>'


def _user_link(user: User | None, *, anonymous: bool = False, viewer: User | None = None) -> str:
    if anonymous:
        return "匿名用户"
    if not user:
        return "系统"
    if viewer and viewer.id == user.id:
        return "你"
    return _link(f"/user/{user.id}", user.username or f"用户 {user.id}")


def _course_link(course: Course | None, *, review_id: int | None = None, comment_id: int | None = None) -> str:
    if not course:
        return "未知课程"
    anchor = f"#comment-{comment_id}" if comment_id else f"#review-{review_id}" if review_id else ""
    return _link(f"/course/{course.id}{anchor}", course.name or f"课程 {course.id}")


def _review_ref_text(review: Review, *, comment_id: int | None = None) -> str:
    course_link = _course_link(review.course, review_id=review.id, comment_id=comment_id)
    author_link = _user_link(review.author, anonymous=bool(review.is_anonymous))
    return f"课程「{course_link}」中 {author_link} 的点评"


def _ref_text(ref_obj, ref_display_class: str | None = None, *, viewer: User | None = None) -> str:
    display_class = ref_display_class or ref_obj.__class__.__name__
    if isinstance(ref_obj, ReviewComment):
        return _review_ref_text(ref_obj.review, comment_id=ref_obj.id)
    if isinstance(ref_obj, Review):
        # 老版 ref_display_class='Course'：点评/更新点评通知只显示课程链接，不点名点评作者
        if display_class == "Course":
            return f"课程「{_course_link(ref_obj.course, review_id=ref_obj.id)}」"
        return _review_ref_text(ref_obj)
    if isinstance(ref_obj, Course):
        return f"课程「{_course_link(ref_obj)}」"
    if isinstance(ref_obj, Teacher):
        return f"老师「{_link(f'/teacher/{ref_obj.id}', ref_obj.name or f'教师 {ref_obj.id}')}」"
    if isinstance(ref_obj, User):
        if viewer and viewer.id == ref_obj.id:
            return "你"
        return f"用户「{_user_link(ref_obj)}」"
    name = getattr(ref_obj, "name", None) or getattr(ref_obj, "title", None) or f"#{getattr(ref_obj, 'id', '')}"
    return escape(str(name))


def build_display_text(
    from_user: User | None,
    operation: str,
    ref_obj,
    *,
    ref_display_class: str | None = None,
    viewer: User | None = None,
) -> str:
    if not ref_obj:
        return ""
    if operation == "block-review" and isinstance(ref_obj, Review):
        course_link = _course_link(ref_obj.course)
        rules_link = _link("/community-rules/", "社区规范")
        return f"您在课程「{course_link}」中的点评因违反{rules_link}，已被屏蔽"
    if operation == "unblock-review" and isinstance(ref_obj, Review):
        return f"您在课程「{_course_link(ref_obj.course)}」中的点评已被解除屏蔽"

    actor = _user_link(from_user)
    # 与老版 Notification.__display_text 一致：尽可能隐去匿名点评相关操作者的真实身份，
    # 避免匿名点评作者在 review/update-review/mention 等通知中被去匿名化。
    if isinstance(ref_obj, Review) and ref_obj.is_anonymous and operation != "comment":
        actor = "匿名用户"
    target = _ref_text(ref_obj, ref_display_class, viewer=viewer)
    operations = {
        "mention": f"在{target}中提到了你",
        "upvote": f"给{target}点了个赞",
        "downvote": f"给{target}点了不推荐",
        "comment": f"评论了{target}",
        "review": f"点评了{target}",
        "update-review": f"更新了{target}",
        "follow": f"关注了{target}",
    }
    return f"{actor} {operations.get(operation, escape(operation) + ' ' + target)}"


def _load_ref_obj(db: Session, notification: Notification):
    model_by_name = {
        "Review": Review,
        "ReviewComment": ReviewComment,
        "Course": Course,
        "User": User,
        "Teacher": Teacher,
    }
    model = model_by_name.get(notification.ref_class or "")
    if not model or notification.ref_obj_id is None:
        return None
    return db.get(model, notification.ref_obj_id)


def serialize_notification(db: Session, notification: Notification) -> NotificationResponse:
    response = NotificationResponse.model_validate(notification)
    ref_obj = _load_ref_obj(db, notification)
    rebuilt = build_display_text(
        notification.from_user,
        notification.operation,
        ref_obj,
        ref_display_class=notification.ref_display_class,
        viewer=notification.to_user,
    )
    response.display_text = rebuilt or notification.display_text
    return response


def create_notification(
    db: Session,
    *,
    to_user: User,
    from_user: User | None,
    operation: str,
    ref_obj,
    ref_display_class: str | None = None,
    commit: bool = True,
) -> Notification:
    notification = Notification(
        to_user=to_user,
        from_user=from_user,
        date=datetime.utcnow().date(),
        time=datetime.utcnow(),
        operation=operation,
        ref_class=ref_obj.__class__.__name__,
        ref_obj_id=getattr(ref_obj, "id", None),
        ref_display_class=ref_display_class or ref_obj.__class__.__name__,
        display_text=build_display_text(
            from_user,
            operation,
            ref_obj,
            ref_display_class=ref_display_class or ref_obj.__class__.__name__,
            viewer=to_user,
        ),
    )
    db.add(notification)
    # 数据库原子自增避免两个并发通知互相覆盖；expire 让当前 Session 下次读取新值。
    db.execute(
        update(User)
        .where(User.id == to_user.id)
        .values(unread_notification_count=func.coalesce(User.unread_notification_count, 0) + 1)
    )
    db.expire(to_user, ["unread_notification_count"])
    if commit:
        db.commit()
        db.refresh(notification)
    return notification


def get_user_notifications(
    db: Session,
    *,
    user: User,
    page: int,
    per_page: int,
) -> PaginatedResponse[NotificationResponse]:
    page = max(page, 1)
    per_page = min(max(per_page, 1), 100)
    query = db.query(Notification).filter(Notification.to_user_id == user.id).order_by(Notification.time.desc())
    total = query.count()
    items = query.offset((page - 1) * per_page).limit(per_page).all()
    pages = ceil(total / per_page) if total else 0
    return PaginatedResponse(
        items=[serialize_notification(db, item) for item in items],
        total=total,
        page=page,
        per_page=per_page,
        pages=pages,
    )


def mark_all_as_read(db: Session, user: User) -> None:
    db.execute(update(User).where(User.id == user.id).values(unread_notification_count=0))
    db.commit()
    db.expire(user, ["unread_notification_count"])


def remove_notification(db: Session, notification_id: int, user: User) -> None:
    notification = db.get(Notification, notification_id)
    if not notification or notification.to_user_id != user.id:
        raise HTTPException(status_code=404, detail="Notification not found")
    db.delete(notification)
    db.commit()
