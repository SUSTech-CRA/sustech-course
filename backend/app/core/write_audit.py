from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.config import settings


logger = logging.getLogger(__name__)


def record_content_write(
    *,
    action: str,
    user_id: int,
    object_type: str,
    object_id: int,
    meta: dict[str, Any] | None = None,
) -> None:
    """Append a lightweight JSONL audit event for new-system content writes."""
    if not settings.WRITE_AUDIT_ENABLED:
        return

    event: dict[str, Any] = {
        "schema_version": 1,
        "source": "ncesnext",
        "event": "content_write",
        "action": action,
        "user_id": user_id,
        "object_type": object_type,
        "object_id": object_id,
        "created_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    }
    if meta:
        event["meta"] = meta

    try:
        path = Path(settings.WRITE_AUDIT_PATH)
        if path.parent != Path("."):
            path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as file:
            file.write(json.dumps(event, ensure_ascii=False, sort_keys=True) + "\n")
    except Exception:
        logger.warning("Failed to write content audit event", exc_info=True)
