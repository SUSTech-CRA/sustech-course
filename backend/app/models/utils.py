from datetime import datetime

from sqlalchemy import Column, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import relationship

from app.models import Base


class RevokedToken(Base):
    __tablename__ = "revoked_token"

    value = Column(String(100), unique=True, primary_key=True)
    revoke_time = Column(DateTime(), default=datetime.utcnow)


class Banner(Base):
    __tablename__ = "banner"

    id = Column(Integer, primary_key=True)
    desktop = Column(Text)
    mobile = Column(Text)
    publish_time = Column(DateTime(), default=datetime.utcnow)


class SearchLog(Base):
    __tablename__ = "search_log"

    id = Column(Integer, primary_key=True, unique=True)
    keyword = Column(String(255))
    user_id = Column(Integer, ForeignKey("users.id"))
    module = Column(String(255))
    page = Column(Integer)
    time = Column(DateTime(), default=datetime.utcnow)

    user = relationship("User")


class Announcement(Base):
    __tablename__ = "announcement"

    id = Column(Integer, primary_key=True)
    author_id = Column(Integer, ForeignKey("users.id"))
    last_editor_id = Column(Integer, ForeignKey("users.id"))
    title = Column(Text)
    content = Column(Text)
    publish_time = Column(DateTime(), default=datetime.utcnow)
    update_time = Column(DateTime(), default=datetime.utcnow)

    author = relationship("User", foreign_keys=[author_id])
    last_editor = relationship("User", foreign_keys=[last_editor_id])
