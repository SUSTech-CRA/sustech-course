from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from app.schemas.course import CourseBrief
from app.schemas.user import TeacherBrief


class TeacherDetail(TeacherBrief):
    model_config = ConfigDict(from_attributes=True)

    dept_id: int | None = None
    office_phone: str | None = None
    gender: str | None = None
    description: str | None = None
    homepage: str | None = None
    research_interest: str | None = None
    access_count: int | None = 0
    image_locked: bool = False
    info_locked: bool = False
    courses: list[CourseBrief] = []
    # 老版教师主页聚合统计：全部课程的点评总数 / 平均分 / 贝叶斯归一化分
    review_count: int = 0
    average_rate: float = 0.0
    normalized_rate: float = 0.0


class TeacherUpdate(BaseModel):
    description: str | None = None
    homepage: str | None = None
    research_interest: str | None = None
    office_phone: str | None = Field(None, max_length=80)
    image: str | None = Field(None, max_length=200)
    info_locked: bool | None = None
    image_locked: bool | None = None


class TeacherHistoryResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    author: int | None = None
    update_time: datetime | None = None
    image: str | None = None
    homepage: str | None = None
    description: str | None = None
    research_interest: str | None = None
