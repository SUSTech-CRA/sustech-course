"""Meilisearch HTTP 薄封装（httpx 直连，不引第三方 SDK）。

查询路径与 reindex 脚本共用。所有异常统一收敛为 MeiliError，
调用方（search_service）据此回落 SQL 路径。
"""

from __future__ import annotations

import time
from typing import Any

import httpx

from app.config import settings

# 任务终态，见 https://www.meilisearch.com/docs/reference/api/tasks
_TASK_DONE = {"succeeded", "failed", "canceled"}


class MeiliError(RuntimeError):
    pass


class MeiliClient:
    def __init__(self, url: str, api_key: str = "", timeout: float = 2.0) -> None:
        headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}
        self._client = httpx.Client(base_url=url.rstrip("/"), headers=headers, timeout=timeout)

    def close(self) -> None:
        self._client.close()

    def _request(self, method: str, path: str, *, json: Any = None, timeout: float | None = None) -> Any:
        try:
            response = self._client.request(method, path, json=json, timeout=timeout)
        except httpx.HTTPError as exc:
            raise MeiliError(f"Meilisearch 请求失败 {method} {path}: {exc}") from exc
        if response.status_code >= 400:
            raise MeiliError(f"Meilisearch 响应异常 {method} {path}: {response.status_code} {response.text[:300]}")
        return response.json() if response.content else None

    def is_healthy(self) -> bool:
        try:
            return self._request("GET", "/health")["status"] == "available"
        except (MeiliError, KeyError, TypeError):
            return False

    def index_exists(self, index_uid: str) -> bool:
        try:
            self._request("GET", f"/indexes/{index_uid}")
            return True
        except MeiliError:
            return False

    def search(self, index_uid: str, params: dict[str, Any]) -> dict[str, Any]:
        return self._request("POST", f"/indexes/{index_uid}/search", json=params)

    def multi_search(self, queries: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return self._request("POST", "/multi-search", json={"queries": queries})["results"]

    # ---- 以下为 reindex 脚本用的写侧端点，均返回 taskUid ----

    def update_settings(self, index_uid: str, index_settings: dict[str, Any]) -> int:
        return self._request("PATCH", f"/indexes/{index_uid}/settings", json=index_settings)["taskUid"]

    def add_documents(self, index_uid: str, documents: list[dict[str, Any]], primary_key: str = "id") -> int:
        return self._request(
            "POST",
            f"/indexes/{index_uid}/documents?primaryKey={primary_key}",
            json=documents,
            timeout=60.0,
        )["taskUid"]

    def delete_index(self, index_uid: str) -> int:
        return self._request("DELETE", f"/indexes/{index_uid}")["taskUid"]

    def swap_indexes(self, pairs: list[tuple[str, str]]) -> int:
        payload = [{"indexes": list(pair)} for pair in pairs]
        return self._request("POST", "/swap-indexes", json=payload)["taskUid"]

    def wait_for_task(self, task_uid: int, timeout_seconds: float = 120.0, poll_interval: float = 0.2) -> None:
        deadline = time.monotonic() + timeout_seconds
        while time.monotonic() < deadline:
            task = self._request("GET", f"/tasks/{task_uid}")
            if task["status"] in _TASK_DONE:
                if task["status"] != "succeeded":
                    raise MeiliError(f"Meilisearch 任务 {task_uid} {task['status']}: {task.get('error')}")
                return
            time.sleep(poll_interval)
        raise MeiliError(f"Meilisearch 任务 {task_uid} 超时（>{timeout_seconds}s）")


_query_client: MeiliClient | None = None


def get_query_client() -> MeiliClient:
    """查询路径共享的进程级客户端（httpx.Client 线程安全，带连接池）。"""
    global _query_client
    if _query_client is None:
        _query_client = MeiliClient(
            settings.MEILISEARCH_URL,
            settings.MEILISEARCH_KEY,
            timeout=settings.MEILISEARCH_TIMEOUT_SECONDS,
        )
    return _query_client
