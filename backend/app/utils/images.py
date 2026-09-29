from __future__ import annotations

import hashlib
import warnings
from datetime import datetime
from io import BytesIO
from typing import BinaryIO
from uuid import uuid4

from PIL import Image, ImageOps

AVATAR_MAX_SIZE = 192
JPEG_MIN_SAVINGS_RATIO = 0.10


class InvalidJpegError(ValueError):
    """待压缩的 JPEG 无法安全解码。"""


def uploaded_image_url(value: str | None, default: str) -> str:
    """存量数据为裸文件名（老磁盘路径），新数据为完整对象存储 URL。"""
    if not value:
        return default
    if value.startswith(("http://", "https://")):
        return value
    return f"/uploads/images/{value}"


def legacy_random_name() -> str:
    raw = f"{datetime.utcnow().isoformat()}{uuid4().hex}"
    digest = hashlib.new("ripemd160")
    digest.update(raw.encode("utf-8"))
    return digest.hexdigest()


def compress_large_jpeg(
    fileobj: BinaryIO,
    *,
    size: int,
    threshold: int,
    quality: int,
) -> BinaryIO:
    """超过阈值的 JPEG 以原尺寸重新编码，收益不足 10% 时保留原文件。

    不按最长边缩放，避免长截图的文字因纵向尺寸很大而被整体缩小。Pillow
    自带的 decompression-bomb 像素检查仍作为异常图片的安全边界。
    """
    fileobj.seek(0)
    if threshold <= 0 or size <= threshold:
        return fileobj

    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", Image.DecompressionBombWarning)
            with Image.open(fileobj) as source:
                if source.format != "JPEG":
                    raise InvalidJpegError("文件内容不是 JPEG")
                image = ImageOps.exif_transpose(source)
                image.load()
    except InvalidJpegError:
        fileobj.seek(0)
        raise
    except (Image.DecompressionBombError, Image.DecompressionBombWarning, OSError, SyntaxError, ValueError) as exc:
        fileobj.seek(0)
        raise InvalidJpegError("JPEG 文件损坏或像素尺寸过大") from exc

    prepared = image
    try:
        if image.mode not in {"RGB", "L"}:
            prepared = image.convert("RGB")
        output = BytesIO()
        prepared.save(output, "JPEG", quality=quality, optimize=True, progressive=True)
    except (OSError, ValueError) as exc:
        raise InvalidJpegError("JPEG 压缩失败") from exc
    finally:
        if prepared is not image:
            prepared.close()
        image.close()
        fileobj.seek(0)

    if output.getbuffer().nbytes > size * (1 - JPEG_MIN_SAVINGS_RATIO):
        output.close()
        return fileobj
    output.seek(0)
    return output


def shrink_avatar(data: bytes, suffix: str) -> tuple[bytes, str]:
    """头像超过 192px 时缩为 PNG 缩略图，返回 (内容, 扩展名)。

    尺寸够小或解码失败时原样返回，与老版 resize_avatar 的回退行为一致。
    """
    try:
        with Image.open(BytesIO(data)) as img:
            if img.width <= AVATAR_MAX_SIZE and img.height <= AVATAR_MAX_SIZE:
                return data, suffix
            img.thumbnail((AVATAR_MAX_SIZE, AVATAR_MAX_SIZE), Image.LANCZOS)
            buffer = BytesIO()
            img.save(buffer, "PNG")
            return buffer.getvalue(), "png"
    except Exception:
        return data, suffix
