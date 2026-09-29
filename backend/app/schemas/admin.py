from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class BannerCreate(BaseModel):
    desktop: str | None = None
    mobile: str | None = None


class BannerResponse(BannerCreate):
    model_config = ConfigDict(from_attributes=True)

    id: int
    publish_time: datetime | None = None


class AnnouncementCreate(BaseModel):
    title: str = Field(min_length=1)
    content: str = Field(min_length=1)


class AnnouncementUpdate(BaseModel):
    title: str | None = Field(None, min_length=1)
    content: str | None = Field(None, min_length=1)


class AnnouncementResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    author_id: int | None = None
    last_editor_id: int | None = None
    title: str | None = None
    content: str | None = None
    publish_time: datetime | None = None
    update_time: datetime | None = None


class CourseSummaryVisibilityUpdate(BaseModel):
    is_hidden: bool
