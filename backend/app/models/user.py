from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, Column, DateTime, Enum, ForeignKey, Integer, String, Table, Text, or_
from sqlalchemy.orm import Session, relationship

from app.core.security import hash_password, verify_password
from app.models import Base
from app.utils.images import uploaded_image_url


follow_course = Table(
    "follow_course",
    Base.metadata,
    Column("course_id", Integer, ForeignKey("courses.id"), primary_key=True),
    Column("user_id", Integer, ForeignKey("users.id"), primary_key=True),
)

join_course = Table(
    "join_course",
    Base.metadata,
    Column("class_id", Integer, ForeignKey("course_classes.id"), primary_key=True),
    Column("student_id", String(20), ForeignKey("students.sno"), primary_key=True),
)

upvote_course = Table(
    "upvote_course",
    Base.metadata,
    Column("user_id", Integer, ForeignKey("users.id")),
    Column("course_id", Integer, ForeignKey("courses.id")),
)

downvote_course = Table(
    "downvote_course",
    Base.metadata,
    Column("user_id", Integer, ForeignKey("users.id")),
    Column("course_id", Integer, ForeignKey("courses.id")),
)

review_course = Table(
    "review_course",
    Base.metadata,
    Column("user_id", Integer, ForeignKey("users.id")),
    Column("course_id", Integer, ForeignKey("courses.id")),
)

follow_user = Table(
    "follow_user",
    Base.metadata,
    Column("follower_id", Integer, ForeignKey("users.id")),
    Column("followed_id", Integer, ForeignKey("users.id")),
)


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    username = Column(String(255), unique=True)
    email = Column(String(255), unique=True)
    password = Column(String(255), nullable=False)
    active = Column(Boolean(), default=True)
    role = Column(String(20), default="User")
    gender = Column(Enum("male", "female", "unknown"), default="unknown")
    identity = Column(Enum("Teacher", "Student"))

    register_time = Column(DateTime(), default=datetime.utcnow)
    confirmed_at = Column(DateTime())
    last_login_time = Column(DateTime())
    last_edit_time = Column(DateTime())
    unread_notification_count = Column(Integer, default=0)

    homepage = Column(String(200))
    description = Column(Text)
    _avatar = Column(String(100))
    is_following_hidden = Column(Boolean, default=False)
    is_profile_hidden = Column(Boolean, default=False)
    is_deleted = Column(Boolean, default=False)

    following_count = Column(Integer, default=0)
    follower_count = Column(Integer, default=0)
    access_count = Column(Integer, default=0)

    token_3rdparty = Column(String(255), nullable=True)

    courses_following = relationship("Course", secondary=follow_course, backref="followers")
    courses_upvoted = relationship("Course", secondary=upvote_course, backref="upvote_users")
    courses_downvoted = relationship("Course", secondary=downvote_course, backref="downvote_users")
    student_info = relationship("Student", back_populates="user", uselist=False)
    teacher_info = relationship("Teacher", back_populates="user", uselist=False)
    reviewed_course = relationship("Course", secondary=review_course, backref="review_users")
    users_following = relationship(
        "User",
        secondary=follow_user,
        primaryjoin=(follow_user.c.follower_id == id),
        secondaryjoin=(follow_user.c.followed_id == id),
        backref="followers",
    )

    def __repr__(self) -> str:
        return f"<User #{self.id} {self.username}>"

    @property
    def confirmed(self) -> bool:
        return self.confirmed_at is not None

    @property
    def is_admin(self) -> bool:
        return self.role == "Admin"

    @property
    def is_student(self) -> bool:
        return self.identity == "Student"

    @property
    def student_id(self) -> str | None:
        return self.info.sno if self.is_student and self.info else None

    @property
    def is_teacher(self) -> bool:
        return self.identity == "Teacher"

    @property
    def info(self) -> Student | Teacher | None:
        if self.is_student:
            return self.student_info
        if self.is_teacher:
            return self.teacher_info
        return None

    @property
    def default_avatar(self) -> str:
        return "/static/image/user.png"

    @property
    def avatar(self) -> str:
        return uploaded_image_url(self._avatar, self.default_avatar)

    @property
    def courses_following_count(self) -> int:
        return len(self.courses_following)

    @property
    def courses_upvoted_count(self) -> int:
        return len(self.courses_upvoted)

    @property
    def courses_downvoted_count(self) -> int:
        return len(self.courses_downvoted)

    @property
    def classes_joined(self) -> list[CourseClass]:
        if self.is_student and self.info:
            return self.info.classes_joined
        return []

    @property
    def courses_joined(self) -> list[CourseClass]:
        if self.is_student and self.info:
            return self.info.courses_joined
        return []

    def set_password(self, password: str) -> None:
        self.password = hash_password(password)
        self.last_edit_time = datetime.utcnow()

    def check_password(self, password: str) -> bool:
        if self.password is None:
            return False
        return verify_password(password, self.password)

    def confirm(self) -> None:
        self.confirmed_at = datetime.utcnow()
        self.last_edit_time = datetime.utcnow()

    @classmethod
    def authenticate(cls, db: Session, login: str, password: str) -> tuple["User | None", bool, bool]:
        user = db.query(cls).filter(or_(cls.username == login, cls.email == login)).first()
        authenticated = bool(user and user.check_password(password))
        return user, authenticated, bool(user and user.confirmed)

    @classmethod
    def authenticate_email(
        cls, db: Session, email: str, password: str
    ) -> tuple["User | None", bool, bool]:
        expanded_student = f"{email}@mail.sustech.edu.cn"
        expanded_teacher = f"{email}@sustech.edu.cn"
        user = (
            db.query(cls)
            .filter(or_(cls.email == email, cls.email == expanded_student, cls.email == expanded_teacher))
            .first()
        )
        authenticated = bool(user and user.check_password(password))
        return user, authenticated, bool(user and user.confirmed)


class Dept(Base):
    __tablename__ = "depts"

    id = Column(Integer, unique=True, primary_key=True)
    name = Column(String(100))
    name_eng = Column(String(200))
    code = Column(String(10))


class Major(Base):
    __tablename__ = "majors"

    id = Column(Integer, unique=True, primary_key=True)
    name = Column(String(200))
    name_eng = Column(String(200))
    code = Column(String(20))


class DeptClass(Base):
    __tablename__ = "dept_classes"

    id = Column(Integer, unique=True, primary_key=True)
    name = Column(String(100))
    dept = Column(Integer, ForeignKey("depts.id"))


class Student(Base):
    __tablename__ = "students"

    sno = Column(String(20), unique=True, primary_key=True)
    name = Column(String(80))
    email = Column(String(80))
    dept_id = Column(Integer, ForeignKey("depts.id"))
    dept_class_id = Column(Integer, ForeignKey("dept_classes.id"))
    major_id = Column(Integer, ForeignKey("majors.id"))
    gender = Column(Enum("male", "female", "unknown"), default="unknown")
    user_id = Column(Integer, ForeignKey("users.id"))

    user = relationship("User", back_populates="student_info")
    dept = relationship("Dept", backref="students")
    dept_class = relationship("DeptClass", backref="students")
    major = relationship("Major")
    classes_joined = relationship(
        "CourseClass",
        secondary=join_course,
        order_by="desc(CourseClass.term)",
        backref="students",
    )
    courses_joined = relationship(
        "CourseClass",
        secondary=join_course,
        order_by="desc(CourseClass.term)",
        overlaps="classes_joined,students",
    )

    def __repr__(self) -> str:
        return f"<Student {self.name} ({self.sno})>"


class TeacherInfoHistory(Base):
    __tablename__ = "teacher_info_history"

    id = Column(Integer, unique=True, primary_key=True)
    teacher_id = Column(Integer, ForeignKey("teachers.id"))
    author = Column(Integer, ForeignKey("users.id"))
    update_time = Column(DateTime)
    _image = Column(String(100))
    homepage = Column(Text)
    description = Column(Text)
    research_interest = Column(Text)

    author_user = relationship("User")

    @property
    def image(self) -> str:
        return uploaded_image_url(self._image, "/static/image/teacher.jpg")


class Teacher(Base):
    __tablename__ = "teachers"

    id = Column(Integer, unique=True, primary_key=True)
    name = Column(String(80))
    dept_id = Column(Integer, ForeignKey("depts.id"))
    email = Column(String(80))
    title = Column(String(80))
    office_phone = Column(String(80))
    gender = Column(Enum("male", "female", "unknown"), default="unknown")
    description = Column(Text)
    homepage = Column(Text)
    research_interest = Column(Text)
    _image = Column(String(100))
    last_edit_time = Column(DateTime)
    image_locked = Column(Boolean, default=False, nullable=False)
    info_locked = Column(Boolean, default=False, nullable=False)
    jwc_id = Column(Integer)
    user_id = Column(Integer, ForeignKey("users.id"))
    access_count = Column(Integer, default=0)

    user = relationship("User", back_populates="teacher_info")
    dept = relationship("Dept", backref="teachers")
    _info_history = relationship(
        "TeacherInfoHistory",
        order_by="desc(TeacherInfoHistory.update_time)",
        backref="teacher",
        lazy="dynamic",
    )

    def __repr__(self) -> str:
        return f"<Teacher {self.id}: {self.name}>"

    @property
    def image(self) -> str:
        return uploaded_image_url(self._image, "/static/image/teacher.jpg")

    @property
    def info_history(self) -> list[TeacherInfoHistory]:
        return self._info_history.all()

    @property
    def info_history_count(self) -> int:
        return len(self.info_history)


class ThirdPartySigninHistory(Base):
    __tablename__ = "third_party_signin_history"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer)
    email = Column(String(255))
    from_app = Column(String(255))
    next_url = Column(String(255))
    challenge = Column(String(255))
    token = Column(String(255))
    signin_time = Column(DateTime, default=datetime.utcnow)
    verify_time = Column(DateTime, default=None)
