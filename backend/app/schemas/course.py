from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.schemas.user import TeacherBrief


def validate_term_format(value: str) -> str:
    if len(value) != 5 or not value[:4].isdigit() or value[4] not in "123":
        raise ValueError("Invalid term format")
    return value


class CourseRateBrief(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    review_count: int = 0
    upvote_count: int = 0
    downvote_count: int = 0
    follow_count: int = 0
    join_count: int = 0
    rate_average: float | None = None
    average_rate: float | None = None
    difficulty: str | None = None
    homework: str | None = None
    grading: str | None = None
    gain: str | None = None
    difficulty_score: str | None = None
    homework_score: str | None = None
    grading_score: str | None = None
    gain_score: str | None = None


class CourseBrief(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    course_code: str | None = None
    teacher_names: str = ""
    term_ids: list[str] = []
    review_count: int = 0
    rate_average: float | None = None
    difficulty_score: str | None = None
    homework_score: str | None = None
    grading_score: str | None = None
    gain_score: str | None = None
    # 仅搜索结果（Meilisearch 路径）填充：HTML 已转义、只含 <mark> 高亮标签的课名
    name_highlighted: str | None = None


class CourseFilterOptions(BaseModel):
    offering_units: list[str] = Field(default_factory=list)


class TeacherCourseGroup(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    teacher: TeacherBrief
    courses: list[CourseBrief] = []


class CourseTermResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    term: str | None = None
    courseries: str | None = None
    kcid: str | None = None
    course_major: str | None = None
    course_type: str | None = None
    course_level: str | None = None
    join_type: str | None = None
    teaching_type: str | None = None
    grading_type: str | None = None
    credit: float | None = None
    hours: int | None = None
    hours_per_week: int | None = None
    campus: str | None = None
    start_week: int | None = None
    end_week: int | None = None


class CourseReviewSummaryContent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    overview: str = Field(min_length=1, max_length=1200)
    strengths: list[str] = Field(max_length=8)
    caveats: list[str] = Field(max_length=8)
    assessment: list[str] = Field(max_length=8)

    @field_validator("strengths", "caveats", "assessment")
    @classmethod
    def validate_summary_items(cls, values: list[str]) -> list[str]:
        cleaned = [value.strip() for value in values if value.strip()]
        if any(len(value) > 500 for value in cleaned):
            raise ValueError("summary item is too long")
        return cleaned


class CourseReviewSummaryResponse(CourseReviewSummaryContent):
    source_review_count: int = Field(ge=1)
    generated_at: datetime


class CourseDetail(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    course_code: str | None = None
    courseries: str | None = None
    course_material_code: str | None = None
    dept: str | None = None
    introduction: str | None = None
    homepage: str | None = None
    admin_announcement: str | None = None
    latest_score: str | None = None
    access_count: int | None = 0
    teachers: list[TeacherBrief] = []
    credit: float | None = None
    hours: int | None = None
    hours_per_week: int | None = None
    description: str | None = None
    description_eng: str | None = None
    teaching_material: str | None = None
    reference_material: str | None = None
    student_requirements: str | None = None
    campus: str | None = None
    course_major: str | None = None
    course_type: str | None = None
    grading_type: str | None = None
    rate: CourseRateBrief | None = None
    review_term_list: list[str] = []
    terms: list[CourseTermResponse] = []
    related_courses: list[CourseBrief] = []
    same_teacher_courses: list[TeacherCourseGroup] = []
    is_upvoted: bool = False
    is_downvoted: bool = False
    is_following: bool = False
    is_joined: bool = False
    has_reviewed: bool = False
    num_blocked_reviews: int = 0
    num_deleted_reviews: int = 0
    ai_summary: CourseReviewSummaryResponse | None = None


class CourseCreate(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    course_code: str | None = Field(None, max_length=80)
    dept_id: int | None = None
    introduction: str | None = None
    homepage: str | None = None
    admin_announcement: str | None = None
    teacher_ids: list[int] = []


class CourseUpdate(BaseModel):
    name: str | None = Field(None, min_length=1, max_length=80)
    course_code: str | None = Field(None, max_length=80)
    dept_id: int | None = None
    introduction: str | None = None
    homepage: str | None = None
    admin_announcement: str | None = None
    teacher_ids: list[int] | None = None


class CourseTeacherUpdate(BaseModel):
    teacher_id: int


class CourseTermStat(BaseModel):
    term: str
    review_count: int
    rate_average: float | None = None


class CourseStats(BaseModel):
    course_id: int
    review_count: int
    rating_distribution: dict[int, int]
    term_distribution: dict[str, int]
    term_stats: list[CourseTermStat] = []


class CourseHistoryResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    author: int | None = None
    update_time: datetime | None = None
    introduction: str | None = None
    homepage: str | None = None


class CourseMaterialEntry(BaseModel):
    name: str
    path: str
    key: str
    is_dir: bool
    size: int | None = None
    last_modified: datetime | None = None
    content_type: str | None = None


class CourseMaterialListResponse(BaseModel):
    course_id: int
    base_code: str
    prefix: str
    path: str = ""
    directories: list[CourseMaterialEntry] = []
    files: list[CourseMaterialEntry] = []


class CourseMaterialDownloadResponse(BaseModel):
    url: str


class CourseTermFilter(BaseModel):
    term: str

    @field_validator("term")
    @classmethod
    def term_must_be_valid(cls, value: str) -> str:
        return validate_term_format(value)
