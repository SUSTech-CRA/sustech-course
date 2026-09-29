import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.models import Base, Course, CourseRate, Review, ReviewComment, User
from app.schemas.review import CommentCreate
from app.schemas.enums import ReviewSortBy
from app.services.course_service import get_course_stats
from app.services.review_service import (
    add_comment,
    delete_comment,
    get_course_reviews,
    set_review_blocked,
    set_review_hidden,
)
from app.services.teacher_service import _teacher_stats
from scripts.repair_course_rates import find_course_rate_mismatches, repair_course_rates


@pytest.fixture
def session_factory():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, autoflush=False)
    yield factory
    engine.dispose()


def _seed_course(session_factory, reviews: list[dict] | None = None):
    reviews = reviews or [{}]
    with session_factory() as db:
        author = User(username="reviewer", email="reviewer@example.invalid", password="unused")
        course = Course(name="聚合测试课程", course_code="TEST001")
        rate = CourseRate(follow_count=7, upvote_count=3)
        course._course_rate = rate
        db.add_all([author, course])
        db.flush()
        review_rows = []
        for index, overrides in enumerate(reviews, start=1):
            values = {
                "difficulty": 2,
                "homework": 2,
                "grading": 2,
                "gain": 2,
                "rate": 8,
                "content": f"测试点评 {index}",
                "term": "20261",
                "is_hidden": False,
                "is_blocked": False,
            }
            values.update(overrides)
            review = Review(author=author, course=course, **values)
            db.add(review)
            review_rows.append(review)
        course.update_rate(db, commit_db=False)
        db.commit()
        return author.id, course.id, [review.id for review in review_rows]


def test_hide_and_unhide_persist_the_correct_course_rate(session_factory):
    author_id, course_id, review_ids = _seed_course(
        session_factory,
        [{"difficulty": 2, "homework": 1, "grading": 3, "gain": 2, "rate": 6}],
    )
    review_id = review_ids[0]

    with session_factory() as db:
        response = set_review_hidden(db, review_id, db.get(User, author_id), True)
        assert response.is_hidden is True
        assert response.course.review_count == 0
        assert response.course.rate_average is None

    with session_factory() as db:
        review = db.get(Review, review_id)
        course = db.get(Course, course_id)
        assert review.is_hidden is True
        assert course.rate.review_count == 0
        assert course.rate._rate_total == 0
        assert course.rate._difficulty_total == 0
        assert course.rate.rate_average is None
        assert get_course_reviews(
            db,
            course_id=course_id,
            user=None,
            page=1,
            per_page=20,
            sort_by=ReviewSortBy.PUBTIME_DESC,
        ).total == 0
        # 隐藏点评仍对作者可见，但不参与课程公开聚合。
        assert get_course_reviews(
            db,
            course_id=course_id,
            user=db.get(User, author_id),
            page=1,
            per_page=20,
            sort_by=ReviewSortBy.PUBTIME_DESC,
        ).total == 1

    with session_factory() as db:
        response = set_review_hidden(db, review_id, db.get(User, author_id), False)
        assert response.is_hidden is False
        assert response.course.review_count == 1
        assert response.course.rate_average == pytest.approx(6.0)

    with session_factory() as db:
        course = db.get(Course, course_id)
        assert db.get(Review, review_id).is_hidden is False
        assert course.rate.review_count == 1
        assert course.rate._rate_total == 6
        assert course.rate._difficulty_total == 2
        assert course.rate.rate_average == pytest.approx(6.0)


def test_block_and_unblock_persist_the_correct_course_rate(session_factory):
    author_id, course_id, review_ids = _seed_course(session_factory)
    review_id = review_ids[0]

    with session_factory() as db:
        response = set_review_blocked(db, review_id, db.get(User, author_id), True)
        assert response.is_blocked is True
        assert response.course.review_count == 0

    with session_factory() as db:
        assert db.get(Course, course_id).rate.review_count == 0
        response = set_review_blocked(db, review_id, db.get(User, author_id), False)
        assert response.is_blocked is False
        assert response.course.review_count == 1

    with session_factory() as db:
        assert db.get(Course, course_id).rate.review_count == 1


def test_course_stats_and_normalized_priors_exclude_hidden_and_blocked_reviews(session_factory):
    _, course_id, _ = _seed_course(
        session_factory,
        [
            {"term": "20261", "rate": 10, "difficulty": 1},
            {"term": "20252", "rate": 1, "difficulty": 3, "is_hidden": True},
            {"term": "20251", "rate": 2, "difficulty": 3, "is_blocked": True},
        ],
    )

    with session_factory() as db:
        course = db.get(Course, course_id)
        stats = get_course_stats(db, course_id)
        assert course.review_term_list == ["20261"]
        assert stats.review_count == 1
        assert stats.rating_distribution == {10: 1}
        assert stats.term_distribution == {"20261": 1}
        assert len(stats.term_stats) == 1
        assert stats.term_stats[0].term == "20261"
        assert stats.term_stats[0].review_count == 1
        assert stats.term_stats[0].rate_average == pytest.approx(10.0)

        normalized = (
            db.query(Course.generic_query_order(CourseRate._rate_total, CourseRate.review_count))
            .filter(CourseRate.id == course_id)
            .scalar()
        )
        assert float(normalized) == pytest.approx(10.0)
        review_count, average_rate, teacher_normalized = _teacher_stats(db, [course])
        assert review_count == 1
        assert average_rate == pytest.approx(10.0)
        assert teacher_normalized == pytest.approx(10.0)


def test_repair_script_finds_and_repairs_stale_rows_without_touching_social_counts(session_factory):
    _, course_id, review_ids = _seed_course(session_factory)
    review_id = review_ids[0]

    # 模拟旧 bug 已提交的状态：点评已隐藏，但 course_rates 仍保留旧聚合。
    with session_factory() as db:
        db.get(Review, review_id).is_hidden = True
        db.commit()

    with session_factory() as db:
        mismatches = find_course_rate_mismatches(db, course_ids=[course_id])
        assert len(mismatches) == 1
        assert mismatches[0].stored.review_count == 1
        assert mismatches[0].expected.review_count == 0
        repair_course_rates(db, mismatches)
        assert find_course_rate_mismatches(db, course_ids=[course_id]) == []

    with session_factory() as db:
        rate = db.get(CourseRate, course_id)
        assert rate.review_count == 0
        assert rate.rate_average is None
        assert rate.follow_count == 7
        assert rate.upvote_count == 3


def test_comment_delete_recounts_from_database_instead_of_stale_relationship(session_factory):
    author_id, _, review_ids = _seed_course(session_factory)
    review_id = review_ids[0]

    with session_factory() as db:
        response = add_comment(db, review_id, CommentCreate(content="测试评论"), db.get(User, author_id))
        assert db.get(Review, review_id).comment_count == 1
        assert db.query(ReviewComment).filter(ReviewComment.review_id == review_id).count() == 1

        delete_comment(db, response.id, db.get(User, author_id))

    with session_factory() as db:
        assert db.get(Review, review_id).comment_count == 0
        assert db.query(ReviewComment).filter(ReviewComment.review_id == review_id).count() == 0
