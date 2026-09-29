from datetime import datetime

from sqlalchemy import Column, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import backref, relationship

from app.models import Base


class Notification(Base):
    __tablename__ = "notifications"

    id = Column(Integer, primary_key=True)
    to_user_id = Column(Integer, ForeignKey("users.id"))
    from_user_id = Column(Integer, ForeignKey("users.id"))
    date = Column(DateTime, default=lambda: datetime.utcnow().date())
    time = Column(DateTime, default=datetime.utcnow)
    operation = Column(String(50), nullable=False)
    ref_class = Column(String(50))
    ref_obj_id = Column(Integer)
    ref_display_class = Column(String(50))
    display_text = Column(Text)

    to_user = relationship(
        "User",
        foreign_keys=[to_user_id],
        backref=backref("notifications", order_by="desc(Notification.time)"),
    )
    from_user = relationship("User", foreign_keys=[from_user_id])
