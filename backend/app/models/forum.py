from datetime import datetime

from sqlalchemy import Column, DateTime, ForeignKey, Integer, String, Table, Text
from sqlalchemy.orm import relationship

from app.models import Base


forum_thread_upvotes = Table(
    "forum_thread_upvotes",
    Base.metadata,
    Column("thread_id", Integer, ForeignKey("forum_threads.id"), primary_key=True),
    Column("author_id", Integer, ForeignKey("users.id"), primary_key=True),
)


class ForumThread(Base):
    __tablename__ = "forum_threads"

    id = Column(Integer, primary_key=True, unique=True)
    author_id = Column(Integer, ForeignKey("users.id"))
    course_id = Column(Integer, ForeignKey("courses.id"))
    upvote = Column(Integer, default=0)
    title = Column(String(200))
    content = Column(Text)
    publish_time = Column(DateTime, default=datetime.utcnow)
    update_time = Column(DateTime, default=datetime.utcnow)
    post_count = Column(Integer, default=0)
    upvote_count = Column(Integer, default=0)

    author = relationship("User", backref="forum_threads")
    posts = relationship("ForumPost", backref="thread", order_by="desc(ForumPost.update_time)")
    upvotes = relationship("User", secondary=forum_thread_upvotes)


forum_post_upvotes = Table(
    "forum_post_upvotes",
    Base.metadata,
    Column("post_id", Integer, ForeignKey("forum_posts.id"), primary_key=True),
    Column("author_id", Integer, ForeignKey("users.id"), primary_key=True),
)


class ForumPost(Base):
    __tablename__ = "forum_posts"

    id = Column(Integer, primary_key=True, unique=True)
    author_id = Column(Integer, ForeignKey("users.id"))
    thread_id = Column(Integer, ForeignKey("forum_threads.id"))
    upvote = Column(Integer, default=0)
    content = Column(Text)
    publish_time = Column(DateTime, default=datetime.utcnow)
    update_time = Column(DateTime, default=datetime.utcnow)
    upvote_count = Column(Integer, default=0)

    author = relationship("User", backref="forum_posts")
    upvotes = relationship("User", secondary=forum_post_upvotes)
