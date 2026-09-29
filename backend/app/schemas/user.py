from datetime import datetime

from pydantic import BaseModel, ConfigDict, EmailStr, Field


class StudentBrief(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    sno: str
    name: str | None = None
    email: str | None = None


class TeacherBrief(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str | None = None
    email: str | None = None
    title: str | None = None
    image: str | None = None


class UserBrief(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    username: str
    avatar: str | None = None
    identity: str | None = None


class UserResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    username: str
    email: EmailStr
    identity: str | None = None
    role: str
    avatar: str
    confirmed: bool
    register_time: datetime | None = None
    unread_notification_count: int = 0
    student: StudentBrief | None = None
    teacher: TeacherBrief | None = None


class UserProfile(UserResponse):
    email: EmailStr | None = None
    homepage: str | None = None
    description: str | None = None
    gender: str | None = None
    # 关注/粉丝数在 is_following_hidden 且非本人/管理员查看时为 None（老版隐藏整块统计）
    following_count: int | None = None
    follower_count: int | None = None
    access_count: int = 0
    is_following_hidden: bool = False
    is_profile_hidden: bool = False
    # 当前查看者是否已关注该用户（未登录/本人恒为 False）
    is_following: bool = False


class UserUpdate(BaseModel):
    username: str | None = Field(None, min_length=1, max_length=30)
    avatar: str | None = Field(None, max_length=200)
    homepage: str | None = Field(None, max_length=200)
    description: str | None = None
    gender: str | None = None
    is_following_hidden: bool | None = None
    is_profile_hidden: bool | None = None


class BindStudentRequest(BaseModel):
    sno: str = Field(min_length=1, max_length=20)


class NotificationResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    from_user_id: int | None = None
    operation: str
    ref_class: str | None = None
    ref_obj_id: int | None = None
    ref_display_class: str | None = None
    display_text: str | None = None
    time: datetime | None = None
