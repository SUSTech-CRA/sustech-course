"""UGC 公开对象存储（Cloudflare R2）：用户上传的内容图片、附件与头像。

对象 key 即公开 URL 路径（UGC_S3_PUBLIC_BASE_URL + "/" + key）。
入库的引用统一存公开 URL，换域名时对存量数据批量替换即可。
"""

from __future__ import annotations

import mimetypes
from functools import lru_cache
from urllib.parse import quote

import boto3
import botocore.config
from botocore.exceptions import BotoCoreError, ClientError
from fastapi import HTTPException

from app.config import settings

IMAGE_PREFIX = "ugc/uploads/images"
FILE_PREFIX = "ugc/uploads/files"
AVATAR_PREFIX = "ugc/uploads/avatar"


@lru_cache
def _get_client():
    if not (settings.UGC_S3_ENDPOINT_URL and settings.UGC_S3_ACCESS_KEY and settings.UGC_S3_SECRET_KEY):
        return None
    return boto3.client(
        "s3",
        endpoint_url=settings.UGC_S3_ENDPOINT_URL,
        aws_access_key_id=settings.UGC_S3_ACCESS_KEY,
        aws_secret_access_key=settings.UGC_S3_SECRET_KEY,
        # R2 兼容性：s3v4 签名 + path 寻址，并关闭新版 boto3 默认附加的 CRC 校验头
        config=botocore.config.Config(
            signature_version="s3v4",
            s3={"addressing_style": "path"},
            request_checksum_calculation="when_required",
        ),
    )


def _client_or_503():
    client = _get_client()
    if client is None or not settings.UGC_S3_BUCKET_NAME:
        raise HTTPException(status_code=503, detail="上传存储未配置，请联系管理员")
    return client


def public_url(key: str) -> str:
    return f"{settings.UGC_S3_PUBLIC_BASE_URL.rstrip('/')}/{key}"


def image_url(stored_filename: str) -> str:
    return public_url(f"{IMAGE_PREFIX}/{stored_filename}")


def guess_content_type(filename: str) -> str:
    return mimetypes.guess_type(filename)[0] or "application/octet-stream"


def attachment_disposition(filename: str) -> str:
    """RFC 5987 编码的下载文件名，让用户下载时拿回上传的原始文件名。"""
    fallback = "".join(ch if 32 <= ord(ch) < 127 and ch not in '"\\' else "_" for ch in filename) or "download"
    return f"attachment; filename=\"{fallback}\"; filename*=UTF-8''{quote(filename)}"


def put_object(key: str, fileobj, *, content_type: str, content_disposition: str | None = None) -> str:
    """上传对象并返回公开 URL。fileobj 为可读二进制文件对象（流式转发，不整读进内存）。"""
    client = _client_or_503()
    extra_args: dict[str, str] = {"ContentType": content_type}
    if content_disposition:
        extra_args["ContentDisposition"] = content_disposition
    try:
        client.upload_fileobj(fileobj, settings.UGC_S3_BUCKET_NAME, key, ExtraArgs=extra_args)
    except (BotoCoreError, ClientError) as exc:
        raise HTTPException(status_code=502, detail="上传存储暂不可用，请稍后再试") from exc
    return public_url(key)


def get_object_bytes(key: str) -> bytes | None:
    client = _get_client()
    if client is None or not settings.UGC_S3_BUCKET_NAME:
        return None
    try:
        response = client.get_object(Bucket=settings.UGC_S3_BUCKET_NAME, Key=key)
        return response["Body"].read()
    except (BotoCoreError, ClientError):
        return None
