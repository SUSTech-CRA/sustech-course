from types import SimpleNamespace

from app.models import Course
from app.services.course_service import (
    COURSE_DETAIL_LIST_LIMIT,
    _related_courses,
    _same_teacher_courses,
)


class RecordingQuery:
    def __init__(self):
        self.ordering = ()
        self.limit_value = None

    def join(self, *_args, **_kwargs):
        return self

    def filter(self, *_args, **_kwargs):
        return self

    def order_by(self, *ordering):
        self.ordering = ordering
        return self

    def limit(self, value):
        self.limit_value = value
        return self

    def all(self):
        return []


class RecordingSession:
    def __init__(self):
        self.queries: list[RecordingQuery] = []

    def query(self, *_args, **_kwargs):
        query = RecordingQuery()
        self.queries.append(query)
        return query


def assert_expanded_stable_query(query: RecordingQuery) -> None:
    assert query.limit_value == COURSE_DETAIL_LIST_LIMIT == 999
    assert len(query.ordering) == 2
    assert query.ordering[1].compare(Course.id.desc())


def test_related_courses_use_expanded_limit_and_stable_tiebreaker():
    db = RecordingSession()

    assert _related_courses(db, SimpleNamespace(id=1, name="测试课程")) == []

    assert_expanded_stable_query(db.queries[0])


def test_same_teacher_courses_use_expanded_limit_and_stable_tiebreaker():
    db = RecordingSession()
    course = SimpleNamespace(id=1, teachers=[SimpleNamespace(id=2)])

    assert _same_teacher_courses(db, course) == []

    assert_expanded_stable_query(db.queries[0])
