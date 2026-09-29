from datetime import datetime

from sqlalchemy import Column, DateTime, ForeignKey, Integer, String, Table, Text
from sqlalchemy.orm import relationship

from app.models import Base


note_upvotes = Table(
    "note_upvotes",
    Base.metadata,
    Column("note_id", Integer, ForeignKey("notes.id"), primary_key=True),
    Column("author_id", Integer, ForeignKey("users.id"), primary_key=True),
)


class Note(Base):
    __tablename__ = "notes"

    id = Column(Integer, primary_key=True, unique=True)
    author_id = Column(Integer, ForeignKey("users.id"))
    course_id = Column(Integer, ForeignKey("courses.id"))
    term = Column(String(10), index=True)
    title = Column(String(200))
    content = Column(Text())
    publish_time = Column(DateTime(), default=datetime.utcnow)
    update_time = Column(DateTime(), default=datetime.utcnow)
    upvote_count = Column(Integer, default=0)
    comment_count = Column(Integer, default=0)

    upvotes = relationship("User", secondary=note_upvotes)
    author = relationship("User", backref="notes")
    comments = relationship("NoteComment", backref="note", order_by="NoteComment.publish_time")


class NoteComment(Base):
    __tablename__ = "note_comments"

    id = Column(Integer, primary_key=True, unique=True)
    note_id = Column(Integer, ForeignKey("notes.id"))
    author_id = Column(Integer, ForeignKey("users.id"))
    content = Column(Text)
    publish_time = Column(DateTime, default=datetime.utcnow)

    author = relationship("User")
