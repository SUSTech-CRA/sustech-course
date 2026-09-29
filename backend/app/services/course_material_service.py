from __future__ import annotations

from functools import lru_cache

import boto3
from botocore.exceptions import BotoCoreError, ClientError, NoCredentialsError
from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.config import _legacy_config_value, settings
from app.models import Course
from app.schemas.course import CourseMaterialEntry, CourseMaterialListResponse


def _clean_relative_path(path: str | None, *, directory: bool) -> str:
    raw_path = (path or "").replace("\\", "/").lstrip("/")
    parts = [part for part in raw_path.split("/") if part]
    if any(part in {".", ".."} for part in parts):
        raise HTTPException(status_code=400, detail="Invalid path")
    cleaned = "/".join(parts)
    if directory and cleaned:
        return f"{cleaned}/"
    return cleaned


@lru_cache
def _get_s3_client():
    if settings.S3_ACCESS_KEY and settings.S3_SECRET_KEY:
        return boto3.client(
            "s3",
            endpoint_url=settings.S3_ENDPOINT_URL or None,
            aws_access_key_id=settings.S3_ACCESS_KEY,
            aws_secret_access_key=settings.S3_SECRET_KEY,
        )
    return _legacy_config_value("S3_CONFIG", None)


def _get_bucket_name() -> str:
    return settings.S3_BUCKET_NAME or _legacy_config_value("S3_BUCKET_NAME", "")


def _course_material_code(course: Course) -> str:
    code = course.course_material_code or course.courseries or course.course_code
    if not code:
        raise HTTPException(status_code=404, detail="Course material library is not configured")
    return code


def _course_material_prefix(course: Course) -> tuple[str, str]:
    code = _course_material_code(course)
    return code, f"course-material/{code}/"


def _s3_or_503():
    client = _get_s3_client()
    bucket = _get_bucket_name()
    if not client or not bucket:
        raise HTTPException(status_code=503, detail="Course material storage is not configured")
    return client, bucket


def _relative_path(key: str, base_prefix: str) -> str:
    return key.removeprefix(base_prefix).lstrip("/")


def _entry_name(key: str) -> str:
    return key.rstrip("/").rsplit("/", 1)[-1]


def list_course_materials(db: Session, course_id: int, path: str | None = None) -> CourseMaterialListResponse:
    course = db.get(Course, course_id)
    if not course:
        raise HTTPException(status_code=404, detail="Course not found")

    client, bucket = _s3_or_503()
    base_code, base_prefix = _course_material_prefix(course)
    relative = _clean_relative_path(path, directory=True)
    prefix = f"{base_prefix}{relative}"

    try:
        response = client.list_objects_v2(Bucket=bucket, Prefix=prefix, Delimiter="/")
    except NoCredentialsError as exc:
        raise HTTPException(status_code=403, detail="Course material credentials are invalid") from exc
    except (BotoCoreError, ClientError) as exc:
        raise HTTPException(status_code=502, detail="Course material storage is unavailable") from exc

    directories = [
        CourseMaterialEntry(
            name=_entry_name(item["Prefix"]),
            path=_relative_path(item["Prefix"], base_prefix),
            key=item["Prefix"],
            is_dir=True,
        )
        for item in response.get("CommonPrefixes", [])
        if item.get("Prefix")
    ]
    files = [
        CourseMaterialEntry(
            name=_entry_name(item["Key"]),
            path=_relative_path(item["Key"], base_prefix),
            key=item["Key"],
            is_dir=False,
            size=item.get("Size"),
            last_modified=item.get("LastModified"),
            content_type=item.get("ContentType"),
        )
        for item in response.get("Contents", [])
        if item.get("Key") and item["Key"] != prefix and not item["Key"].endswith("/")
    ]

    directories.sort(key=lambda item: item.name.lower())
    files.sort(key=lambda item: item.name.lower())
    return CourseMaterialListResponse(
        course_id=course.id,
        base_code=base_code,
        prefix=base_prefix,
        path=relative,
        directories=directories,
        files=files,
    )


def get_course_material_download_url(db: Session, course_id: int, path: str) -> str:
    course = db.get(Course, course_id)
    if not course:
        raise HTTPException(status_code=404, detail="Course not found")

    client, bucket = _s3_or_503()
    _, base_prefix = _course_material_prefix(course)
    relative = _clean_relative_path(path, directory=False)
    if not relative:
        raise HTTPException(status_code=400, detail="Invalid path")
    key = f"{base_prefix}{relative}"

    try:
        return client.generate_presigned_url(
            "get_object",
            Params={"Bucket": bucket, "Key": key},
            ExpiresIn=600,
        )
    except NoCredentialsError as exc:
        raise HTTPException(status_code=403, detail="Course material credentials are invalid") from exc
    except (BotoCoreError, ClientError) as exc:
        raise HTTPException(status_code=502, detail="Course material storage is unavailable") from exc
