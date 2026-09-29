import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core.database import SessionLocal
from app.models import (
    Base,
    Course,
    CourseClass,
    CourseRate,
    CourseTerm,
    Review,
    ReviewComment,
    Student,
    User,
    downvote_course,
    follow_course,
    follow_user,
    join_course,
    review_course,
    review_upvotes,
    upvote_course,
)
from app.services.course_service import toggle_course_follow, toggle_course_join, toggle_course_vote
from app.schemas.course import CourseRateBrief
from app.services.review_service import toggle_review_upvote
from app.services.user_service import toggle_follow_user
from scripts.import_sustech_courses import ImportStats, flush_and_refresh_course_codes
from scripts.repair_course_rates import (
    find_count_mismatches,
    find_relation_duplicates,
    repair_count_mismatches,
    repair_relation_duplicates,
)


@pytest.fixture
def session_factory():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, autoflush=False)
    yield factory
    engine.dispose()


def test_application_session_enables_autoflush_by_default():
    assert SessionLocal.kw["autoflush"] is True


def test_reading_missing_course_rate_does_not_attach_or_insert_a_row(session_factory):
    with session_factory() as db:
        course = Course(name="无聚合行课程", course_code="NO-RATE")
        db.add(course)
        db.commit()
        course_id = course.id

    with session_factory() as db:
        course = db.get(Course, course_id)
        pending_before = set(db.new)
        assert course.rate.review_count == 0
        assert CourseRateBrief.model_validate(course.rate).review_count == 0
        assert set(db.new) == pending_before
        db.query(User.id).all()
        assert db.get(CourseRate, course_id) is None


def test_import_flushes_pending_terms_before_refreshing_course_code(session_factory):
    with session_factory() as db:
        course = Course(name="导入测试", course_code="OLD")
        db.add(course)
        db.flush()
        db.add(CourseTerm(course=course, term="20251", courseries="OLD"))
        db.commit()

        db.add(CourseTerm(course=course, term="20261", courseries="NEW"))
        stats = ImportStats()
        flush_and_refresh_course_codes(db, {course}, stats)

        assert course.course_code == "NEW"
        assert stats.refreshed_course_codes == 1


def test_audit_deduplicates_relations_and_repairs_all_derived_counts(session_factory):
    with session_factory() as db:
        author = User(username="author", email="author@example.invalid", password="unused")
        other = User(username="other", email="other@example.invalid", password="unused")
        student_user = User(
            username="student",
            email="student@example.invalid",
            password="unused",
            identity="Student",
        )
        student = Student(sno="12345678", user=student_user)
        course = Course(name="计数审计课程", course_code="COUNT")
        rate = CourseRate(
            review_count=1,
            _rate_total=8,
            _rate_average=8,
            _difficulty_total=2,
            _homework_total=2,
            _grading_total=2,
            _gain_total=2,
            upvote_count=99,
            downvote_count=99,
            follow_count=99,
            join_count=99,
        )
        course._course_rate = rate
        course_class = CourseClass(course=course, term="20261", cno="COUNT-1")
        review = Review(
            author=author,
            course=course,
            difficulty=2,
            homework=2,
            grading=2,
            gain=2,
            rate=8,
            content="点评",
            term="20261",
            comment_count=99,
            upvote_count=99,
        )
        db.add_all([author, other, student, course, course_class, review])
        db.flush()
        db.add(ReviewComment(review=review, author=other, content="评论"))
        db.execute(review_upvotes.insert().values(review_id=review.id, author_id=other.id))
        db.execute(follow_course.insert().values(course_id=course.id, user_id=other.id))
        db.execute(join_course.insert().values(class_id=course_class.id, student_id=student.sno))
        db.execute(downvote_course.insert().values(course_id=course.id, user_id=author.id))
        # 这些旧表没有唯一键，构造重复 pair 验证去重。
        for table, values in (
            (upvote_course, {"course_id": course.id, "user_id": other.id}),
            (follow_user, {"follower_id": other.id, "followed_id": author.id}),
            (review_course, {"course_id": course.id, "user_id": author.id}),
        ):
            db.execute(table.insert().values(**values))
            db.execute(table.insert().values(**values))
        author.follower_count = 99
        other.following_count = 99
        db.commit()
        course_id = course.id

    with session_factory() as db:
        duplicates = find_relation_duplicates(db, course_ids=[course_id])
        assert {row.table for row in duplicates} == {"follow_user", "review_course", "upvote_course"}
        assert find_count_mismatches(db, course_ids=[course_id])

        repair_relation_duplicates(db, duplicates, commit_db=False)
        db.flush()
        mismatches = find_count_mismatches(db, course_ids=[course_id])
        repair_count_mismatches(db, mismatches, commit_db=False)
        db.commit()

        assert find_relation_duplicates(db, course_ids=[course_id]) == []
        assert find_count_mismatches(db, course_ids=[course_id]) == []
        rate = db.get(CourseRate, course_id)
        assert (rate.upvote_count, rate.downvote_count, rate.follow_count, rate.join_count) == (1, 1, 1, 1)
        review = db.query(Review).filter(Review.course_id == course_id).one()
        assert (review.comment_count, review.upvote_count) == (1, 1)


def test_active_counter_write_paths_recompute_from_database(session_factory):
    with session_factory() as db:
        author = User(username="writer", email="writer@example.invalid", password="unused")
        voter = User(username="voter", email="voter@example.invalid", password="unused")
        student_user = User(
            username="joiner",
            email="joiner@example.invalid",
            password="unused",
            identity="Student",
        )
        student = Student(sno="87654321", user=student_user)
        course = Course(name="写路径课程", course_code="WRITE")
        course._course_rate = CourseRate()
        course_class = CourseClass(course=course, term="20261", cno="WRITE-1")
        review = Review(
            author=author,
            course=course,
            difficulty=2,
            homework=2,
            grading=2,
            gain=2,
            rate=8,
            content="点评",
            term="20261",
        )
        db.add_all([author, voter, student, course, course_class, review])
        db.commit()
        author_id, voter_id, student_user_id = author.id, voter.id, student_user.id
        course_id, review_id = course.id, review.id

    with session_factory() as db:
        toggle_review_upvote(db, review_id, db.get(User, voter_id), True)
        toggle_course_vote(db, course_id, db.get(User, voter_id), "upvote", True)
        toggle_course_follow(db, course_id, db.get(User, voter_id), True)
        toggle_course_join(db, course_id, db.get(User, student_user_id), True)
        toggle_follow_user(db, db.get(User, voter_id), author_id, True)

        rate = db.get(CourseRate, course_id)
        assert db.get(Review, review_id).upvote_count == 1
        assert (rate.upvote_count, rate.follow_count, rate.join_count) == (1, 1, 1)
        assert db.get(User, voter_id).following_count == 1
        assert db.get(User, author_id).follower_count == 1

        toggle_review_upvote(db, review_id, db.get(User, voter_id), False)
        toggle_course_vote(db, course_id, db.get(User, voter_id), "upvote", False)
        toggle_course_follow(db, course_id, db.get(User, voter_id), False)
        toggle_course_join(db, course_id, db.get(User, student_user_id), False)
        toggle_follow_user(db, db.get(User, voter_id), author_id, False)

        rate = db.get(CourseRate, course_id)
        assert db.get(Review, review_id).upvote_count == 0
        assert (rate.upvote_count, rate.follow_count, rate.join_count) == (0, 0, 0)
        assert db.get(User, voter_id).following_count == 0
        assert db.get(User, author_id).follower_count == 0
