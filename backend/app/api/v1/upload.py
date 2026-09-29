from pathlib import Path

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile, status
from sqlalchemy.orm import Session

from app.config import settings
from app.core.database import get_db
from app.dependencies import get_current_active_user
from app.models import ImageStore, User
from app.schemas.upload import UploadResponse
from app.services import ugc_storage
from app.utils.images import InvalidJpegError, compress_large_jpeg, legacy_random_name

router = APIRouter()

_KEY_PREFIXES = {"image": ugc_storage.IMAGE_PREFIX, "file": ugc_storage.FILE_PREFIX}


def _select_upload(upload: UploadFile | None, file: UploadFile | None) -> UploadFile:
    selected = upload or file
    if selected is None:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="No file uploaded")
    return selected


def _ensure_allowed(filename: str | None, upload_type: str) -> str:
    suffix = Path(filename or "").suffix.lower().lstrip(".")
    allowed = settings.ALLOWED_EXTENSIONS.get(upload_type, set())
    if not suffix or suffix not in allowed:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="File type disallowed")
    return suffix


def _save_upload(
    *,
    upload_type: str,
    upload: UploadFile | None,
    file: UploadFile | None,
    db: Session,
    user: User,
) -> UploadResponse:
    selected = _select_upload(upload, file)
    suffix = _ensure_allowed(selected.filename, upload_type)
    stored_filename = f"{legacy_random_name()}.{suffix}"

    body = selected.file
    body.seek(0, 2)
    size = body.tell()
    body.seek(0)
    if settings.MAX_CONTENT_LENGTH and size > settings.MAX_CONTENT_LENGTH:
        raise HTTPException(status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, detail="File too large")

    if upload_type == "image" and suffix in {"jpg", "jpeg"}:
        try:
            body = compress_large_jpeg(
                body,
                size=size,
                threshold=settings.UGC_JPEG_COMPRESS_THRESHOLD_BYTES,
                quality=settings.UGC_JPEG_QUALITY,
            )
        except InvalidJpegError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="JPEG 图片损坏或像素尺寸过大") from exc

    # 附件带原始文件名下载；图片内联展示
    disposition = None
    if upload_type == "file":
        disposition = ugc_storage.attachment_disposition(selected.filename or stored_filename)
    url = ugc_storage.put_object(
        f"{_KEY_PREFIXES[upload_type]}/{stored_filename}",
        body,
        content_type=ugc_storage.guess_content_type(stored_filename),
        content_disposition=disposition,
    )

    image = ImageStore(author=user, filename=selected.filename, stored_filename=stored_filename)
    db.add(image)
    db.commit()
    db.refresh(image)
    return UploadResponse(
        id=image.id,
        filename=image.filename or "",
        stored_filename=image.stored_filename or "",
        url=url,
        resource_url=url,
    )


# 同步端点：boto3 上传是阻塞调用，交给 FastAPI 线程池执行，避免卡住事件循环
@router.post("/image", response_model=UploadResponse, status_code=201)
def upload_image(
    upload: UploadFile | None = File(None),
    file: UploadFile | None = File(None),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_active_user),
):
    return _save_upload(upload_type="image", upload=upload, file=file, db=db, user=user)


@router.post("/file", response_model=UploadResponse, status_code=201)
def upload_file(
    upload: UploadFile | None = File(None),
    file: UploadFile | None = File(None),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_active_user),
):
    return _save_upload(upload_type="file", upload=upload, file=file, db=db, user=user)
