from __future__ import annotations

from collections import Counter
from datetime import datetime
from decimal import Decimal

from sqlalchemy import JSON, Boolean, Column, DateTime, Float, ForeignKey, Integer, String, Table, Text, UniqueConstraint, func, inspect as sa_inspect, select
from sqlalchemy.orm import Session, backref, relationship

from app.models import Base
from app.utils.images import uploaded_image_url


course_teachers = Table(
    "course_teachers",
    Base.metadata,
    Column("course_id", Integer, ForeignKey("courses.id")),
    Column("teacher_id", Integer, ForeignKey("teachers.id")),
    UniqueConstraint("course_id", "teacher_id"),
)


class CourseTimeLocation(Base):
    __tablename__ = "course_time_locations"

    id = Column(Integer, primary_key=True)
    course_id = Column(Integer, ForeignKey("courses.id"))
    class_id = Column(Integer, ForeignKey("course_classes.id"))
    weekday = Column(Integer)
    begin_hour = Column(Integer)
    num_hours = Column(Integer)
    location = Column(String(80))
    note = Column(String(200))

    @property
    def hours_list(self):
        if not self.begin_hour or not self.num_hours:
            return []
        return range(self.begin_hour, self.begin_hour + self.num_hours)

    @property
    def hours_list_display(self) -> str:
        return ",".join(map(str, self.hours_list))

    @property
    def time_display(self) -> str | None:
        if not self.weekday or not self.hours_list_display:
            return None
        return f"{self.weekday}({self.hours_list_display})"

    @property
    def time_location_display(self) -> str | None:
        if not self.location or not self.time_display:
            return None
        return f"{self.location}: {self.time_display}"


class CourseClass(Base):
    __tablename__ = "course_classes"

    id = Column(Integer, unique=True, primary_key=True)
    course_id = Column(Integer, ForeignKey("courses.id"))
    term = Column(String(10), index=True)
    cno = Column(String(20))

    time_locations = relationship("CourseTimeLocation", backref="class")

    __table_args__ = (UniqueConstraint("term", "cno"),)

    def __repr__(self) -> str:
        return f"{self.cno}@{self.term}"

    @property
    def time_locations_display(self) -> str:
        return "; ".join(
            row.time_location_display for row in self.time_locations if row.time_location_display is not None
        )


class CourseTerm(Base):
    __tablename__ = "course_terms"

    id = Column(Integer, unique=True, primary_key=True)
    course_id = Column(Integer, ForeignKey("courses.id"))
    term = Column(String(10), index=True)
    courseries = Column(String(20))
    kcid = Column(String(256))
    course_major = Column(String(20))
    course_type = Column(String(20))
    course_level = Column(String(20))
    join_type = Column(String(20))
    teaching_type = Column(String(20))
    grading_type = Column(String(20))
    teaching_material = Column(Text)
    reference_material = Column(Text)
    student_requirements = Column(Text)
    description = Column(Text())
    description_eng = Column(Text())
    credit = Column(Float)
    hours = Column(Integer)
    hours_per_week = Column(Integer)
    class_numbers = Column(String(200))
    campus = Column(String(20))
    start_week = Column(Integer)
    end_week = Column(Integer)

    def __repr__(self) -> str:
        try:
            return f"{self.course}@{self.term}"
        except Exception:
            return ""


class CourseInfoHistory(Base):
    __tablename__ = "course_info_history"

    id = Column(Integer, unique=True, primary_key=True)
    course_id = Column(Integer, ForeignKey("courses.id"))
    author = Column(Integer, ForeignKey("users.id"))
    update_time = Column(DateTime)
    introduction = Column(Text)
    homepage = Column(Text)

    author_user = relationship("User")


class CourseReviewSummary(Base):
    """公开点评的离线 AI 派生摘要；表由独立 DDL 创建，不走 Alembic。"""

    __tablename__ = "course_review_summary"

    course_id = Column(Integer, primary_key=True)
    summary_json = Column(JSON, nullable=False)
    model = Column(String(100), nullable=False)
    prompt_version = Column(String(32), nullable=False)
    source_fingerprint = Column(String(64), nullable=False)
    source_review_count = Column(Integer, nullable=False)
    generated_at = Column(DateTime, nullable=False)
    prompt_tokens = Column(Integer)
    completion_tokens = Column(Integer)
    total_tokens = Column(Integer)
    reasoning_tokens = Column(Integer)
    is_hidden = Column(Boolean, nullable=False, default=False)


class Course(Base):
    __tablename__ = "courses"

    id = Column(Integer, unique=True, primary_key=True)
    name = Column(String(80), index=True)
    course_code = Column(String(80), index=True)
    dept_id = Column(Integer, ForeignKey("depts.id"))
    introduction = Column(Text)
    homepage = Column(Text)
    last_edit_time = Column(DateTime)
    access_count = Column(Integer, default=0)
    _image = Column(String(100))
    admin_announcement = Column(Text)
    latest_score = Column(Text)
    score_type_pf = Column(Boolean, default=False)
    score_semester = Column(Integer, default=0)
    course_material_code = Column(String(80))

    terms = relationship("CourseTerm", backref="course", order_by="desc(CourseTerm.term)", lazy="dynamic")
    classes = relationship("CourseClass", backref="course", lazy="dynamic", order_by="desc(CourseClass.term)")
    _dept = relationship("Dept", backref="courses", lazy="joined")
    teachers = relationship(
        "Teacher",
        secondary=course_teachers,
        backref=backref("courses", lazy="dynamic"),
        order_by="Teacher.id",
        lazy="joined",
    )
    reviews = relationship(
        "Review",
        backref=backref("course", lazy="joined"),
        order_by="desc(Review.update_time)",
        lazy="dynamic",
    )
    notes = relationship(
        "Note",
        backref=backref("course", lazy="joined"),
        order_by="desc(Note.upvote_count), desc(Note.id)",
        lazy="dynamic",
    )
    forum_threads = relationship("ForumThread", backref="course", order_by="desc(ForumThread.update_time)", lazy="dynamic")
    shares = relationship(
        "Share",
        backref="course",
        order_by="desc(Share.upvote_count), desc(Share.id)",
        lazy="dynamic",
    )
    _course_rate = relationship("CourseRate", backref="course", uselist=False, lazy="joined")
    _info_history = relationship("CourseInfoHistory", order_by="desc(CourseInfoHistory.update_time)", backref="course", lazy="dynamic")

    def __repr__(self) -> str:
        return f"{self.name}({','.join(sorted(self.teacher_name_list))})"

    @property
    def info_history(self) -> list[CourseInfoHistory]:
        return self._info_history.all()

    @property
    def info_history_count(self) -> int:
        return len(self.info_history)

    @property
    def teacher_id_list(self) -> list[int]:
        return [teacher.id for teacher in self.teachers]

    @property
    def teacher_name_list(self) -> list[str]:
        return [teacher.name for teacher in self.teachers if teacher.name]

    @property
    def registered_teacher_id_list(self) -> list[int]:
        return [teacher.user_id for teacher in self.teachers if teacher.user_id]

    @property
    def dept(self) -> str | None:
        return self._dept.name if self._dept else None

    @property
    def course_rate(self) -> CourseRate:
        if self._course_rate:
            return self._course_rate
        # 读取属性不应给 Session 挂入待写对象；缺行时仅返回零值视图。
        # 所有写路径通过 ensure/lock_course_rate 显式创建并持久化。
        return CourseRate(
            id=self.id,
            _difficulty_total=0,
            _homework_total=0,
            _grading_total=0,
            _gain_total=0,
            _rate_total=0,
            _rate_average=None,
            review_count=0,
            upvote_count=0,
            downvote_count=0,
            follow_count=0,
            join_count=0,
        )

    def ensure_course_rate(self, db: Session) -> CourseRate:
        if self._course_rate is None:
            self._course_rate = CourseRate(id=self.id)
            db.add(self._course_rate)
        return self._course_rate

    def lock_course_rate(self, db: Session) -> CourseRate:
        """锁定冗余聚合行，串行化同一课程的计数重算。"""
        course_rate = self.ensure_course_rate(db)
        if sa_inspect(course_rate).persistent:
            # 全局开启 autoflush 后，这里必须先拿聚合行锁再刷新 Review 变更，
            # 否则并发事务可能在等待锁之前就把部分状态写入数据库。
            with db.no_autoflush:
                db.query(CourseRate.id).filter(CourseRate.id == self.id).with_for_update().one()
        else:
            # 新课程没有可锁的旧行；INSERT 本身会持有该键的写锁。
            db.flush()
        return course_rate

    @property
    def rate(self) -> CourseRate:
        return self.course_rate

    @classmethod
    def generic_query_order(cls, rate_total, review_count):
        from app.models.review import Review

        aggregate_filter = (Review.is_hidden.is_(False), Review.is_blocked.is_(False))
        avg_rate = select(func.coalesce(func.avg(Review.rate), 0)).where(*aggregate_filter).scalar_subquery()
        avg_rate_count = select(
            func.coalesce(func.count(Review.id) / func.nullif(func.count(func.distinct(Review.course_id)), 0), 0)
        ).where(*aggregate_filter).scalar_subquery()
        return (rate_total + avg_rate * avg_rate_count) / func.nullif(review_count + avg_rate_count, 0)

    @classmethod
    def _QUERY_ORDER(cls):
        normalized_rate = cls.generic_query_order(CourseRate._rate_total, CourseRate.review_count)
        return func.IF(CourseRate.review_count > 0, normalized_rate, 0)

    @classmethod
    def QUERY_ORDER(cls):
        return cls._QUERY_ORDER().desc()

    @classmethod
    def REVERSE_QUERY_ORDER(cls):
        return cls._QUERY_ORDER()

    @property
    def review_count(self) -> int:
        return self.course_rate.review_count or 0

    @property
    def upvote_count(self) -> int:
        return self.course_rate.upvote_count or 0

    @property
    def downvote_count(self) -> int:
        return self.course_rate.downvote_count or 0

    @property
    def follow_count(self) -> int:
        return self.course_rate.follow_count or 0

    @property
    def teachers_count(self) -> int:
        return len(self.teachers)

    @property
    def terms_count(self) -> int:
        return self.terms.count()

    def _aggregate_reviews_query(self):
        """点评公开聚合口径：排除用户隐藏和管理员屏蔽的点评。"""
        from app.models.review import Review

        return self.reviews.filter(Review.is_hidden.is_(False), Review.is_blocked.is_(False))

    @property
    def review_term_list(self) -> list[str]:
        terms = {review.term for review in self._aggregate_reviews_query() if review.term}
        return sorted(terms, reverse=True)

    @property
    def review_term_dist(self) -> Counter:
        return Counter(review.term for review in self._aggregate_reviews_query() if review.term)

    @property
    def review_rate_dist(self) -> Counter:
        return Counter(review.rate for review in self._aggregate_reviews_query() if review.rate)

    @property
    def teacher_names_display(self) -> str:
        if self.teachers_count == 0:
            return "未知"
        return ", ".join(self.teacher_name_list)

    @property
    def teacher_names_display_short(self) -> str:
        if self.teachers_count == 0:
            return "未知"
        value = ", ".join(self.teacher_name_list[:3])
        if self.teachers_count > 3:
            value += "..."
        return value

    @property
    def teacher_names_bracket_short(self) -> str:
        return f"（{self.teacher_names_display_short}）" if self.teachers_count > 0 else ""

    @property
    def name_with_teachers_short(self) -> str:
        return self.name + self.teacher_names_bracket_short

    @property
    def image(self) -> str:
        return uploaded_image_url(self._image, "/static/image/user.png")

    @property
    def latest_term(self) -> CourseTerm | None:
        return self.terms.first()

    @property
    def term_ids(self) -> list[str]:
        return [term.term for term in self.terms if term.term]

    def _latest_attr(self, name: str):
        latest = self.latest_term
        return getattr(latest, name) if latest else None

    @property
    def courseries(self):
        return self._latest_attr("courseries")

    @property
    def kcid(self):
        return self._latest_attr("kcid")

    @property
    def course_major(self):
        return self._latest_attr("course_major")

    @property
    def course_type(self):
        return self._latest_attr("course_type")

    @property
    def course_level(self):
        return self._latest_attr("course_level")

    @property
    def grading_type(self):
        return self._latest_attr("grading_type")

    @property
    def join_type(self):
        return self._latest_attr("join_type")

    @property
    def teaching_type(self):
        return self._latest_attr("teaching_type")

    @property
    def teaching_material(self):
        return self._latest_attr("teaching_material")

    @property
    def reference_material(self):
        return self._latest_attr("reference_material")

    @property
    def student_requirements(self):
        return self._latest_attr("student_requirements")

    @property
    def description(self):
        return self._latest_attr("description")

    @property
    def description_eng(self):
        return self._latest_attr("description_eng")

    @property
    def credit(self):
        return self._latest_attr("credit")

    @property
    def hours(self):
        return self._latest_attr("hours")

    @property
    def hours_per_week(self):
        return self._latest_attr("hours_per_week")

    @property
    def class_numbers(self):
        return self._latest_attr("class_numbers")

    @property
    def campus(self):
        return self._latest_attr("campus")

    @property
    def start_week(self):
        return self._latest_attr("start_week")

    @property
    def end_week(self):
        return self._latest_attr("end_week")

    def update_rate(self, db: Session, commit_db: bool = True) -> CourseRate:
        from app.models.review import Review

        course_rate = self.lock_course_rate(db)
        # 显式 flush 表达聚合边界，并让传入自定义 autoflush=False Session 的
        # 脚本/测试同样按最新 create/update/delete/hide/block 状态查询。
        db.flush()
        review_rows = (
            db.query(Review.difficulty, Review.homework, Review.grading, Review.gain, Review.rate)
            .filter(
                Review.course_id == self.id,
                Review.is_hidden.is_(False),
                Review.is_blocked.is_(False),
            )
            # MySQL REPEATABLE READ 下使用当前读，避免事务在等待 course_rates
            # 行锁前已经建立的快照漏掉刚提交的并发点评变更。
            .with_for_update()
            .all()
        )
        course_rate.review_count = len(review_rows)
        course_rate._difficulty_total = sum(row.difficulty or 0 for row in review_rows)
        course_rate._homework_total = sum(row.homework or 0 for row in review_rows)
        course_rate._grading_total = sum(row.grading or 0 for row in review_rows)
        course_rate._gain_total = sum(row.gain or 0 for row in review_rows)
        course_rate._rate_total = sum(row.rate or 0 for row in review_rows)
        course_rate.update_average()
        db.add(course_rate)
        if commit_db:
            db.commit()
        return course_rate


class CourseRate(Base):
    __tablename__ = "course_rates"

    id = Column(Integer, ForeignKey("courses.id"), primary_key=True)
    _difficulty_total = Column(Integer, default=0, index=True)
    _homework_total = Column(Integer, default=0, index=True)
    _grading_total = Column(Integer, default=0, index=True)
    _gain_total = Column(Integer, default=0, index=True)
    _rate_total = Column(Integer, default=0, index=True)
    _rate_average = Column(Float, default=0, index=True)
    review_count = Column(Integer, default=0, index=True)
    upvote_count = Column(Integer, default=0, index=True)
    downvote_count = Column(Integer, default=0, index=True)
    follow_count = Column(Integer, default=0, index=True)
    join_count = Column(Integer, default=0, index=True)

    @property
    def difficulty(self) -> str | None:
        if self.review_count:
            return {1: "简单", 2: "中等", 3: "困难"}.get(round(self._difficulty_total / self.review_count))
        return None

    @property
    def difficulty_score(self) -> str | None:
        if self.review_count:
            rank = 100 - (self._difficulty_total / self.review_count - 1) * 100 / 2
            return f"{rank:.2f}"
        return None

    @property
    def homework(self) -> str | None:
        if self.review_count:
            return {1: "很少", 2: "中等", 3: "很多"}.get(round(self._homework_total / self.review_count))
        return None

    @property
    def homework_score(self) -> str | None:
        if self.review_count:
            rank = 100 - (self._homework_total / self.review_count - 1) * 100 / 2
            return f"{rank:.2f}"
        return None

    @property
    def grading(self) -> str | None:
        if self.review_count:
            return {1: "超好", 2: "一般", 3: "杀手"}.get(round(self._grading_total / self.review_count))
        return None

    @property
    def grading_score(self) -> str | None:
        if self.review_count:
            rank = 100 - (self._grading_total / self.review_count - 1) * 100 / 2
            return f"{rank:.2f}"
        return None

    @property
    def gain(self) -> str | None:
        if self.review_count:
            return {1: "很多", 2: "一般", 3: "没有"}.get(round(self._gain_total / self.review_count))
        return None

    @property
    def gain_score(self) -> str | None:
        if self.review_count:
            rank = 100 - (self._gain_total / self.review_count - 1) * 100 / 2
            return f"{rank:.2f}"
        return None

    @property
    def average_rate(self) -> Decimal | None:
        if self.review_count:
            return Decimal("%.1f" % (self._rate_average or 0))
        return None

    @property
    def rate_average(self) -> float | None:
        return self._rate_average if self.review_count else None

    def update_average(self) -> None:
        if self.review_count:
            self._rate_average = 1.0 * (self._rate_total or 0) / self.review_count
        else:
            self._rate_average = None
