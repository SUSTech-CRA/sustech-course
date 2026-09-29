from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.schemas.course import CourseBrief, validate_term_format
from app.schemas.user import UserBrief


class ReviewCreate(BaseModel):
    course_id: int
    term: str
    difficulty: int = Field(ge=1, le=3)
    homework: int = Field(ge=1, le=3)
    grading: int = Field(ge=1, le=3)
    gain: int = Field(ge=1, le=3)
    rate: int = Field(ge=1, le=10)
    content: str = Field(min_length=1)
    is_anonymous: bool = False
    only_visible_to_student: bool = False

    @field_validator("term")
    @classmethod
    def term_must_be_valid(cls, value: str) -> str:
        return validate_term_format(value)


class ReviewUpdate(BaseModel):
    term: str | None = None
    difficulty: int | None = Field(None, ge=1, le=3)
    homework: int | None = Field(None, ge=1, le=3)
    grading: int | None = Field(None, ge=1, le=3)
    gain: int | None = Field(None, ge=1, le=3)
    rate: int | None = Field(None, ge=1, le=10)
    content: str | None = Field(None, min_length=1)
    is_anonymous: bool | None = None
    only_visible_to_student: bool | None = None

    @field_validator("term")
    @classmethod
    def term_must_be_valid(cls, value: str | None) -> str | None:
        return validate_term_format(value) if value is not None else value


class ReviewResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    difficulty: int
    homework: int
    grading: int
    gain: int
    rate: int
    content: str
    publish_time: datetime | None = None
    update_time: datetime | None = None
    upvote_count: int = 0
    comment_count: int = 0
    is_anonymous: bool = False
    only_visible_to_student: bool = False
    is_hidden: bool = False
    is_blocked: bool = False
    term: str
    author: UserBrief | None = None
    course: CourseBrief | None = None
    difficulty_display: str
    homework_display: str
    grading_display: str
    gain_display: str
    term_display: str
    is_upvoted: bool = False
    # 仅搜索结果（Meilisearch 路径）填充：HTML 已转义、只含 <mark> 高亮标签的纯文本摘要
    content_snippet: str | None = None


class CommentCreate(BaseModel):
    content: str = Field(min_length=1, max_length=500)


class CommentResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    review_id: int | None = None
    author_id: int | None = None
    content: str
    publish_time: datetime | None = None
    author: UserBrief | None = None


class ReviewHistoryResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    review_id: int | None = None
    operation: str | None = None
    operation_time: datetime | None = None
    operation_user_id: int | None = None
    content: str | None = None
