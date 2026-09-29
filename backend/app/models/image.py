from datetime import datetime

from sqlalchemy import Column, DateTime, ForeignKey, Integer, String
from sqlalchemy.orm import relationship

from app.models import Base


class ImageStore(Base):
    __tablename__ = "image_store"

    id = Column(Integer, primary_key=True, unique=True)
    author_id = Column(Integer, ForeignKey("users.id"))
    filename = Column(String(256))
    upload_time = Column(DateTime(), default=datetime.utcnow)
    stored_filename = Column(String(80), unique=True)

    author = relationship("User", foreign_keys=[author_id], uselist=False)
