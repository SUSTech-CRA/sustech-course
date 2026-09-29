from datetime import datetime

from sqlalchemy import Column, DateTime, ForeignKey, Integer, String, Table, Text
from sqlalchemy.orm import relationship

from app.models import Base


share_upvotes = Table(
    "share_upvotes",
    Base.metadata,
    Column("share_id", Integer, ForeignKey("shares.id"), primary_key=True),
    Column("author_id", Integer, ForeignKey("users.id"), primary_key=True),
)


class Share(Base):
    __tablename__ = "shares"

    id = Column(Integer, primary_key=True, unique=True)
    author_id = Column(Integer, ForeignKey("users.id"))
    course_id = Column(Integer, ForeignKey("courses.id"))
    upvote = Column(Integer, default=0)
    filename = Column(String(256))
    description = Column(Text)
    upload_time = Column(DateTime, default=datetime.utcnow)
    stored_filename = Column(String(80), unique=True)
    upvote_count = Column(Integer, default=0)
    comment_count = Column(Integer, default=0)

    author = relationship("User", backref="shares")
    upvotes = relationship("User", secondary=share_upvotes)
    comments = relationship("ShareComment", backref="share", order_by="ShareComment.publish_time")


class ShareComment(Base):
    __tablename__ = "share_comments"

    id = Column(Integer, primary_key=True, unique=True)
    author_id = Column(Integer, ForeignKey("users.id"))
    share_id = Column(Integer, ForeignKey("shares.id"))
    content = Column(Text)
    publish_time = Column(DateTime, default=datetime.utcnow)

    author = relationship("User")
