from io import BytesIO
from math import ceil
from pathlib import Path

from fastapi import HTTPException
from sqlalchemy import delete, func, update
from sqlalchemy.orm import Session

from app.config import settings
from app.models import Course, ImageStore, Review, Student, User, follow_user
from app.schemas.common import PaginatedResponse
from app.schemas.course import CourseBrief
from app.schemas.review import ReviewResponse
from app.schemas.user import UserBrief, UserProfile, UserUpdate
from app.services import ugc_storage
from app.services.course_service import serialize_course_brief
from app.services.notification_service import create_notification
from app.services.review_service import filter_reviews_by_visibility, serialize_review
from app.utils.images import legacy_random_name, shrink_avatar
from app.utils.username import normalize_username, validate_username_value


def normalize_homepage(value: str | None) -> str | None:
    """与老版一致：非空主页地址自动补全 http:// 前缀。"""
    if value is None:
        return None
    value = value.strip()
    if value and not value.startswith(("http://", "https://")):
        value = f"http://{value}"
    return value


def resolve_uploaded_image(db: Session, value: str) -> str:
    """校验图片引用必须是已上传的图片文件，返回存储文件名。

    兼容三种引用形态：裸文件名（前端上传响应的 stored_filename）、
    老版磁盘路径 /uploads/images/x、UGC 对象存储公开 URL。
    """
    stored = value.strip()
    for prefix in (f"{ugc_storage.public_url(ugc_storage.IMAGE_PREFIX)}/", "/uploads/images/"):
        stored = stored.removeprefix(prefix)
    if not stored or "/" in stored or "\\" in stored:
        raise HTTPException(status_code=422, detail="无效的图片")
    image = db.query(ImageStore).filter(ImageStore.stored_filename == stored).first()
    if not image:
        raise HTTPException(status_code=422, detail="图片必须先通过上传接口上传")
    suffix = Path(stored).suffix.lower().lstrip(".")
    if suffix not in settings.ALLOWED_EXTENSIONS.get("image", set()):
        raise HTTPException(status_code=422, detail="图片格式不支持")
    return stored


def make_avatar(db: Session, value: str) -> str:
    """把已上传图片处理成头像（≤192px）存入 R2 avatar/ 目录，返回公开 URL。"""
    stored = resolve_uploaded_image(db, value)
    data = ugc_storage.get_object_bytes(f"{ugc_storage.IMAGE_PREFIX}/{stored}")
    if data is None:
        # 兼容仍在本地磁盘上的存量图片
        try:
            data = (Path(settings.UPLOAD_FOLDER) / "images" / stored).read_bytes()
        except OSError:
            raise HTTPException(status_code=422, detail="图片必须先通过上传接口上传") from None
    suffix = Path(stored).suffix.lower().lstrip(".")
    data, suffix = shrink_avatar(data, suffix)
    key = f"{ugc_storage.AVATAR_PREFIX}/{legacy_random_name()}.{suffix}"
    return ugc_storage.put_object(key, BytesIO(data), content_type=ugc_storage.guess_content_type(key))


def serialize_user_brief(user: User) -> UserBrief:
    return UserBrief(
        id=user.id,
        username=user.username,
        avatar=user.avatar,
        identity=user.identity,
    )


def _can_view_profile(user: User, viewer: User | None) -> bool:
    return not user.is_profile_hidden or bool(viewer and (viewer.id == user.id or viewer.is_admin))


def _can_view_following(user: User, viewer: User | None) -> bool:
    return not user.is_following_hidden or bool(viewer and (viewer.id == user.id or viewer.is_admin))


def _get_visible_user(db: Session, user_id: int, viewer: User | None) -> User:
    user = db.get(User, user_id)
    if not user or user.is_deleted or not _can_view_profile(user, viewer):
        raise HTTPException(status_code=404, detail="User not found")
    return user


def serialize_user_profile(user: User, viewer: User | None = None) -> UserProfile:
    is_self = bool(viewer and viewer.id == user.id)
    is_admin_viewer = bool(viewer and viewer.is_admin)
    show_following_stats = not user.is_following_hidden or is_self or is_admin_viewer
    return UserProfile(
        id=user.id,
        username=user.username,
        email=user.email if is_self else None,
        identity=user.identity,
        role=user.role,
        avatar=user.avatar,
        confirmed=user.confirmed,
        register_time=user.register_time,
        # 未读数是查看者自己的隐私信息，他人主页不返回真实值
        unread_notification_count=(user.unread_notification_count or 0) if is_self else 0,
        # 学号/真实姓名/学生邮箱仅本人和管理员可见，防止点评作者被实名化
        student=user.student_info if (is_self or is_admin_viewer) else None,
        teacher=user.teacher_info,
        homepage=user.homepage,
        description=user.description,
        gender=user.gender,
        following_count=(user.following_count or 0) if show_following_stats else None,
        follower_count=(user.follower_count or 0) if show_following_stats else None,
        access_count=user.access_count or 0,
        is_following_hidden=bool(user.is_following_hidden),
        is_profile_hidden=bool(user.is_profile_hidden),
        is_following=bool(viewer and not is_self and user in viewer.users_following),
    )


def get_user_profile(db: Session, user_id: int, viewer: User | None) -> UserProfile:
    user = _get_visible_user(db, user_id, viewer)
    db.execute(
        update(User)
        .where(User.id == user.id)
        .values(access_count=func.coalesce(User.access_count, 0) + 1)
    )
    db.commit()
    db.refresh(user)
    return serialize_user_profile(user, viewer)


def update_profile(db: Session, user: User, payload: UserUpdate) -> UserProfile:
    data = payload.model_dump(exclude_unset=True)
    avatar_value = data.pop("avatar", None)
    if "username" in data and data["username"] is not None:
        username = normalize_username(data["username"])
        if username != user.username:
            error = validate_username_value(username)
            if error:
                raise HTTPException(status_code=422, detail=error)
            exists = db.query(User).filter(User.username == username, User.id != user.id).first()
            if exists:
                raise HTTPException(status_code=409, detail="该用户名已被他人使用")
        data["username"] = username
    if "homepage" in data:
        data["homepage"] = normalize_homepage(data["homepage"])
    for key, value in data.items():
        setattr(user, key, value)
    if avatar_value:
        user._avatar = make_avatar(db, avatar_value)
    db.add(user)
    db.commit()
    db.refresh(user)
    return serialize_user_profile(user, user)


def bind_student(db: Session, user: User, sno: str) -> UserProfile:
    if user.identity != "Student":
        raise HTTPException(status_code=403, detail="Student identity required")
    student = db.get(Student, sno)
    if not student:
        raise HTTPException(status_code=404, detail="Student not found")
    user.student_info = student
    db.commit()
    db.refresh(user)
    return serialize_user_profile(user, user)


def toggle_follow_user(db: Session, follower: User, followed_id: int, enabled: bool) -> UserProfile:
    if followed_id == follower.id:
        raise HTTPException(status_code=400, detail="Cannot follow yourself")
    locked_rows = (
        db.query(User.id, User.is_deleted)
        .filter(User.id.in_(sorted((follower.id, followed_id))))
        .order_by(User.id)
        .with_for_update()
        .all()
    )
    locked_by_id = {row.id: bool(row.is_deleted) for row in locked_rows}
    if followed_id not in locked_by_id or locked_by_id[followed_id]:
        raise HTTPException(status_code=404, detail="User not found")
    followed = db.get(User, followed_id)
    pair = (follow_user.c.follower_id == follower.id) & (follow_user.c.followed_id == followed.id)
    existing = bool(
        db.query(follow_user.c.follower_id)
        .filter(pair)
        .with_for_update()
        .first()
    )
    # 旧表没有唯一键；先删再按需插入，顺带把当前 pair 的历史重复行归一为一条。
    db.execute(delete(follow_user).where(pair))
    if enabled:
        db.execute(follow_user.insert().values(follower_id=follower.id, followed_id=followed.id))
    if enabled and not existing:
        create_notification(db, to_user=followed, from_user=follower, operation="follow", ref_obj=followed, commit=False)
    db.flush()
    follower.following_count = len(
        {
            target_id
            for (target_id,) in db.query(follow_user.c.followed_id)
            .filter(follow_user.c.follower_id == follower.id)
            .with_for_update()
            .all()
        }
    )
    followed.follower_count = len(
        {
            source_id
            for (source_id,) in db.query(follow_user.c.follower_id)
            .filter(follow_user.c.followed_id == followed.id)
            .with_for_update()
            .all()
        }
    )
    db.commit()
    return serialize_user_profile(followed, follower)


def _paginate(items: list, page: int, per_page: int):
    page = max(page, 1)
    per_page = min(max(per_page, 1), 100)
    total = len(items)
    start = (page - 1) * per_page
    return items[start : start + per_page], total, ceil(total / per_page) if total else 0


def get_user_reviews(db: Session, user_id: int, viewer: User | None, page: int, per_page: int) -> PaginatedResponse[ReviewResponse]:
    user = _get_visible_user(db, user_id, viewer)
    query = filter_reviews_by_visibility(db.query(Review), viewer)
    query = query.filter_by(author_id=user.id).order_by(Review.update_time.desc())
    # 与老版 User.reviews 一致：只有本人能在个人主页看到自己的匿名点评，
    # 否则会通过"该用户的点评列表"这一事实去匿名化。
    if not (viewer and viewer.id == user.id):
        query = query.filter(Review.is_anonymous.is_(False))
    total = query.count()
    items = query.offset((page - 1) * per_page).limit(per_page).all()
    return PaginatedResponse(items=[serialize_review(item, viewer) for item in items], total=total, page=page, per_page=per_page, pages=ceil(total / per_page) if total else 0)


def get_following_courses(user: User, viewer: User | None, page: int, per_page: int) -> PaginatedResponse[CourseBrief]:
    if not _can_view_following(user, viewer):
        raise HTTPException(status_code=404, detail="User not found")
    items, total, pages = _paginate(user.courses_following, page, per_page)
    return PaginatedResponse(items=[serialize_course_brief(item) for item in items], total=total, page=page, per_page=per_page, pages=pages)


def get_joined_courses(db: Session, user_id: int, viewer: User, page: int, per_page: int) -> PaginatedResponse[CourseBrief]:
    user = _get_visible_user(db, user_id, viewer)
    if not _can_view_following(user, viewer):
        raise HTTPException(status_code=404, detail="User not found")
    seen: set[int] = set()
    courses: list[Course] = []
    for cls in user.classes_joined:
        if cls.course and cls.course_id not in seen:
            seen.add(cls.course_id)
            courses.append(cls.course)
    items, total, pages = _paginate(courses, page, per_page)
    return PaginatedResponse(items=[serialize_course_brief(item) for item in items], total=total, page=page, per_page=per_page, pages=pages)


def get_followers(db: Session, user_id: int, viewer: User | None, page: int, per_page: int) -> PaginatedResponse[UserBrief]:
    user = _get_visible_user(db, user_id, viewer)
    if not _can_view_following(user, viewer):
        raise HTTPException(status_code=404, detail="User not found")
    followers = [item for item in user.followers if not item.is_deleted]
    items, total, pages = _paginate(followers, page, per_page)
    return PaginatedResponse(items=[serialize_user_brief(item) for item in items], total=total, page=page, per_page=per_page, pages=pages)


def get_followings(db: Session, user_id: int, viewer: User | None, page: int, per_page: int) -> PaginatedResponse[UserBrief]:
    user = _get_visible_user(db, user_id, viewer)
    if not _can_view_following(user, viewer):
        raise HTTPException(status_code=404, detail="User not found")
    followings = [item for item in user.users_following if not item.is_deleted]
    items, total, pages = _paginate(followings, page, per_page)
    return PaginatedResponse(items=[serialize_user_brief(item) for item in items], total=total, page=page, per_page=per_page, pages=pages)
