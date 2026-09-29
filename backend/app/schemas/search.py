from __future__ import annotations

from pydantic import BaseModel


class SearchSuggestCourse(BaseModel):
    id: int
    name: str
    course_code: str | None = None
    teacher_names: str = ""
    review_count: int = 0


class SearchSuggestTeacher(BaseModel):
    id: int
    name: str
    title: str | None = None


class SearchSuggestResponse(BaseModel):
    courses: list[SearchSuggestCourse] = []
    teachers: list[SearchSuggestTeacher] = []
