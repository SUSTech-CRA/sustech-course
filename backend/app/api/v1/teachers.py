from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.dependencies import get_current_active_user
from app.models import User
from app.schemas.teacher import TeacherDetail, TeacherHistoryResponse, TeacherUpdate
from app.services.teacher_service import get_teacher_detail, get_teacher_history, update_teacher

router = APIRouter()


@router.get("/{teacher_id}", response_model=TeacherDetail)
def teacher_detail(teacher_id: int, db: Session = Depends(get_db)):
    return get_teacher_detail(db, teacher_id)


@router.patch("/{teacher_id}", response_model=TeacherDetail)
def patch_teacher(teacher_id: int, payload: TeacherUpdate, db: Session = Depends(get_db), user: User = Depends(get_current_active_user)):
    return update_teacher(db, teacher_id, payload, user)


@router.get("/{teacher_id}/history", response_model=list[TeacherHistoryResponse])
def teacher_history(teacher_id: int, db: Session = Depends(get_db), user: User = Depends(get_current_active_user)):
    return get_teacher_history(db, teacher_id, user)
