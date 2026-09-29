import json

from app.core import write_audit


def test_content_write_audit_is_disabled_by_default(tmp_path, monkeypatch):
    audit_path = tmp_path / "write_audit.jsonl"
    monkeypatch.setattr(write_audit.settings, "WRITE_AUDIT_ENABLED", False)
    monkeypatch.setattr(write_audit.settings, "WRITE_AUDIT_PATH", str(audit_path))

    write_audit.record_content_write(
        action="review.create",
        user_id=1,
        object_type="review",
        object_id=2,
    )

    assert not audit_path.exists()


def test_content_write_audit_appends_jsonl(tmp_path, monkeypatch):
    audit_path = tmp_path / "audit" / "write_audit.jsonl"
    monkeypatch.setattr(write_audit.settings, "WRITE_AUDIT_ENABLED", True)
    monkeypatch.setattr(write_audit.settings, "WRITE_AUDIT_PATH", str(audit_path))

    write_audit.record_content_write(
        action="comment.create",
        user_id=1,
        object_type="comment",
        object_id=2,
        meta={"review_id": 3},
    )

    lines = audit_path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    event = json.loads(lines[0])
    assert event["source"] == "ncesnext"
    assert event["event"] == "content_write"
    assert event["action"] == "comment.create"
    assert event["user_id"] == 1
    assert event["object_type"] == "comment"
    assert event["object_id"] == 2
    assert event["meta"] == {"review_id": 3}
    assert "created_at" in event
