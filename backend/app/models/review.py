from __future__ import annotations

from datetime import datetime

import html2text
from sqlalchemy import Boolean, CheckConstraint, Column, DateTime, ForeignKey, Integer, String, Table, Text
from sqlalchemy.orm import relationship

from app.models import Base


review_upvotes = Table(
    "review_upvotes",
    Base.metadata,
    Column("review_id", Integer, ForeignKey("reviews.id"), primary_key=True),
    Column("author_id", Integer, ForeignKey("users.id"), primary_key=True),
)


class Review(Base):
    __tablename__ = "reviews"

    id = Column(Integer, primary_key=True, unique=True)
    difficulty = Column(Integer, CheckConstraint("difficulty>=1 and difficulty<=3"))
    homework = Column(Integer, CheckConstraint("homework>=1 and homework<=3"))
    grading = Column(Integer, CheckConstraint("grading>=1 and grading<=3"))
    gain = Column(Integer, CheckConstraint("gain>=1 and gain<=3"))
    rate = Column(Integer, CheckConstraint("rate>=1 and rate<=10"))
    content = Column(Text())

    publish_time = Column(DateTime(), default=datetime.utcnow)
    update_time = Column(DateTime(), default=datetime.utcnow)
    upvote_count = Column(Integer, default=0)
    comment_count = Column(Integer, default=0)

    author_id = Column(Integer, ForeignKey("users.id"))
    course_id = Column(Integer, ForeignKey("courses.id"))
    term = Column(String(10), index=True)

    is_anonymous = Column(Boolean, default=False)
    only_visible_to_student = Column(Boolean, default=False)
    is_hidden = Column(Boolean, default=False)
    is_blocked = Column(Boolean, default=False)
    filter_rule = Column(Text())

    upvote_users = relationship("User", backref="upvoted_reviews", secondary=review_upvotes)
    comments = relationship(
        "ReviewComment",
        backref="review",
        lazy="joined",
        order_by="ReviewComment.publish_time",
    )
    author = relationship("User", lazy="joined")

    @property
    def content_text(self) -> str:
        return html2text.html2text(self.content or "")

    @property
    def term_display(self) -> str:
        if not self.term or len(self.term) < 5:
            return "未知"
        if self.term[4] == "1":
            return f"{self.term[0:4]}秋"
        if self.term[4] == "2":
            return f"{int(self.term[0:4]) + 1}春"
        if self.term[4] == "3":
            return f"{int(self.term[0:4]) + 1}夏"
        return "未知"

    @property
    def difficulty_display(self) -> str:
        return {1: "简单", 2: "中等", 3: "困难"}.get(self.difficulty, "未知")

    @property
    def homework_display(self) -> str:
        return {1: "很少", 2: "中等", 3: "很多"}.get(self.homework, "未知")

    @property
    def grading_display(self) -> str:
        return {1: "超好", 2: "一般", 3: "杀手"}.get(self.grading, "未知")

    @property
    def gain_display(self) -> str:
        return {1: "很多", 2: "一般", 3: "没有"}.get(self.gain, "未知")


class ReviewComment(Base):
    __tablename__ = "review_comments"

    id = Column(Integer, primary_key=True, unique=True)
    review_id = Column(Integer, ForeignKey("reviews.id"))
    author_id = Column(Integer, ForeignKey("users.id"))
    content = Column(Text)
    publish_time = Column(DateTime, default=datetime.utcnow)

    author = relationship("User")


class ReviewHistory(Base):
    __tablename__ = "review_history"

    id = Column(Integer, primary_key=True, unique=True)
    difficulty = Column(Integer)
    homework = Column(Integer)
    grading = Column(Integer)
    gain = Column(Integer)
    rate = Column(Integer)
    content = Column(Text())
    publish_time = Column(DateTime, default=datetime.utcnow)
    update_time = Column(DateTime, default=datetime.utcnow)
    author_id = Column(Integer)
    course_id = Column(Integer)
    term = Column(String(10))
    is_anonymous = Column(Boolean, default=False)
    only_visible_to_student = Column(Boolean, default=False)
    is_hidden = Column(Boolean, default=False)
    is_blocked = Column(Boolean, default=False)
    review_id = Column(Integer)
    operation_time = Column(DateTime, default=datetime.utcnow)
    operation_user_id = Column(Integer)
    operation = Column(String(20))


class ReviewCommentHistory(Base):
    __tablename__ = "review_comment_history"

    id = Column(Integer, primary_key=True, unique=True)
    review_id = Column(Integer)
    author_id = Column(Integer)
    content = Column(Text)
    publish_time = Column(DateTime, default=datetime.utcnow)
    comment_id = Column(Integer)
    operation_time = Column(DateTime, default=datetime.utcnow)
    operation_user_id = Column(Integer)
    operation = Column(String(20))
