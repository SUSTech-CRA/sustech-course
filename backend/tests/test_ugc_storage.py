from io import BytesIO

from fastapi import UploadFile
from PIL import Image

from app.api.v1 import upload as upload_api
from app.models import User
from app.services import ugc_storage
from app.utils.images import (
    AVATAR_MAX_SIZE,
    InvalidJpegError,
    compress_large_jpeg,
    shrink_avatar,
    uploaded_image_url,
)


def _png_bytes(width: int, height: int) -> bytes:
    buffer = BytesIO()
    Image.new("RGB", (width, height), "white").save(buffer, "PNG")
    return buffer.getvalue()


def _jpeg_bytes(width: int, height: int, *, quality: int) -> bytes:
    buffer = BytesIO()
    Image.effect_noise((width, height), 80).convert("RGB").save(buffer, "JPEG", quality=quality)
    return buffer.getvalue()


def test_public_url_joins_base_and_key(monkeypatch):
    monkeypatch.setattr(ugc_storage.settings, "UGC_S3_PUBLIC_BASE_URL", "https://nces-ugcdata.ncesnext.com/")
    assert ugc_storage.public_url("ugc/uploads/files/a.pdf") == "https://nces-ugcdata.ncesnext.com/ugc/uploads/files/a.pdf"
    assert ugc_storage.image_url("a.png") == "https://nces-ugcdata.ncesnext.com/ugc/uploads/images/a.png"


def test_guess_content_type():
    assert ugc_storage.guess_content_type("a.png") == "image/png"
    assert ugc_storage.guess_content_type("a.unknown-ext") == "application/octet-stream"


def test_attachment_disposition_keeps_ascii_and_encodes_unicode():
    value = ugc_storage.attachment_disposition('数据结构"期末".pdf')
    assert value.startswith('attachment; filename="')
    assert '"' not in value.split('filename="', 1)[1].split('"', 1)[0].replace("_", "")
    assert "filename*=UTF-8''%E6%95%B0%E6%8D%AE" in value

    plain = ugc_storage.attachment_disposition("notes.pdf")
    assert 'filename="notes.pdf"' in plain


def test_put_object_returns_503_when_unconfigured(monkeypatch):
    import pytest
    from fastapi import HTTPException

    monkeypatch.setattr(ugc_storage, "_get_client", lambda: None)
    with pytest.raises(HTTPException) as exc_info:
        ugc_storage.put_object("ugc/uploads/images/a.png", BytesIO(b""), content_type="image/png")
    assert exc_info.value.status_code == 503


def test_shrink_avatar_keeps_small_images():
    data = _png_bytes(64, 64)
    shrunk, suffix = shrink_avatar(data, "png")
    assert shrunk == data
    assert suffix == "png"


def test_shrink_avatar_resizes_large_images_to_png():
    shrunk, suffix = shrink_avatar(_png_bytes(800, 400), "jpg")
    assert suffix == "png"
    with Image.open(BytesIO(shrunk)) as img:
        assert max(img.width, img.height) <= AVATAR_MAX_SIZE


def test_shrink_avatar_falls_back_on_invalid_data():
    shrunk, suffix = shrink_avatar(b"not an image", "png")
    assert shrunk == b"not an image"
    assert suffix == "png"


def test_compress_large_jpeg_keeps_small_file_unchanged():
    data = _jpeg_bytes(320, 240, quality=95)
    source = BytesIO(data)

    result = compress_large_jpeg(source, size=len(data), threshold=len(data), quality=70)

    assert result is source
    assert result.read() == data


def test_compress_large_jpeg_reencodes_without_resizing_long_screenshot():
    data = _jpeg_bytes(320, 4000, quality=100)

    result = compress_large_jpeg(BytesIO(data), size=len(data), threshold=1, quality=70)
    compressed = result.read()

    assert len(compressed) <= len(data) * 0.9
    with Image.open(BytesIO(compressed)) as image:
        assert image.format == "JPEG"
        assert image.size == (320, 4000)
        assert image.info.get("progressive") == 1


def test_compress_large_jpeg_keeps_already_compact_file():
    data = _jpeg_bytes(640, 480, quality=30)
    source = BytesIO(data)

    result = compress_large_jpeg(source, size=len(data), threshold=1, quality=70)

    assert result is source
    assert result.read() == data


def test_compress_large_jpeg_rejects_invalid_large_file():
    import pytest

    with pytest.raises(InvalidJpegError):
        compress_large_jpeg(BytesIO(b"not a jpeg"), size=10, threshold=1, quality=70)


def test_image_upload_sends_compressed_jpeg_to_object_storage(monkeypatch):
    data = _jpeg_bytes(1200, 800, quality=100)
    captured: dict[str, object] = {}

    def fake_put_object(key, fileobj, *, content_type, content_disposition=None):
        captured.update(
            key=key,
            body=fileobj.read(),
            content_type=content_type,
            content_disposition=content_disposition,
        )
        return f"https://ugc.example/{key}"

    class FakeSession:
        def add(self, image):
            captured["image_store"] = image

        def commit(self):
            pass

        def refresh(self, image):
            image.id = 123

    monkeypatch.setattr(ugc_storage, "put_object", fake_put_object)
    monkeypatch.setattr(upload_api, "legacy_random_name", lambda: "a" * 40)
    monkeypatch.setattr(upload_api.settings, "UGC_JPEG_COMPRESS_THRESHOLD_BYTES", 1)
    monkeypatch.setattr(upload_api.settings, "UGC_JPEG_QUALITY", 70)

    response = upload_api._save_upload(
        upload_type="image",
        upload=UploadFile(file=BytesIO(data), filename="photo.jpeg"),
        file=None,
        db=FakeSession(),
        user=User(id=1, username="tester", password="unused"),
    )

    compressed = captured["body"]
    assert isinstance(compressed, bytes)
    assert len(compressed) <= len(data) * 0.9
    assert captured["content_type"] == "image/jpeg"
    assert captured["content_disposition"] is None
    assert str(captured["key"]).endswith(".jpeg")
    assert response.id == 123
    assert response.url.startswith("https://ugc.example/ugc/uploads/images/")


def test_uploaded_image_url_handles_legacy_and_absolute():
    assert uploaded_image_url(None, "/static/image/user.png") == "/static/image/user.png"
    assert uploaded_image_url("abc.png", "/static/image/user.png") == "/uploads/images/abc.png"
    absolute = "https://nces-ugcdata.ncesnext.com/ugc/uploads/avatar/abc.png"
    assert uploaded_image_url(absolute, "/static/image/user.png") == absolute
