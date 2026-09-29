#!/usr/bin/env python3
"""全量重建 Meilisearch 搜索索引（MySQL → Meilisearch，单向只读）。

策略：每个索引先写入 <name>_staging，三个 staging 全部就绪后一次
swap-indexes 原子切换，再删除 staging（切换后 staging 持有旧数据）。
任何一步失败则线上索引保持原样，脚本以非零退出（journald 可见）。

由 systemd timer 每 5 分钟触发（meilisearch/systemd/），也可手动执行：

    python scripts/reindex_search.py [--dry-run]
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

BACKEND_ROOT = Path(__file__).resolve().parents[1]
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from app.config import settings
from app.core.database import SessionLocal
from app.search.documents import INDEX_SETTINGS, build_all_documents
from app.search.meili_client import MeiliClient, MeiliError

STAGING_SUFFIX = "_staging"


def _log(message: str) -> None:
    print(f"[reindex_search] {message}", flush=True)


def reindex(client: MeiliClient, documents_by_index: dict[str, list[dict]]) -> None:
    for index_uid, documents in documents_by_index.items():
        staging_uid = index_uid + STAGING_SUFFIX
        if client.index_exists(staging_uid):
            client.wait_for_task(client.delete_index(staging_uid))
        # PATCH settings 会自动创建索引；文档写入前配置好 searchable/ranking
        client.wait_for_task(client.update_settings(staging_uid, INDEX_SETTINGS[index_uid]))
        client.wait_for_task(client.add_documents(staging_uid, documents))
        # 首次运行时正式索引不存在，swap 要求两侧都存在——建一个空索引即可
        if not client.index_exists(index_uid):
            client.wait_for_task(client.update_settings(index_uid, INDEX_SETTINGS[index_uid]))
        _log(f"{staging_uid} 就绪：{len(documents)} 个文档")

    client.wait_for_task(client.swap_indexes([(uid, uid + STAGING_SUFFIX) for uid in documents_by_index]))
    for index_uid in documents_by_index:
        client.wait_for_task(client.delete_index(index_uid + STAGING_SUFFIX))
    _log("swap 完成，线上索引已切换")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dry-run", action="store_true", help="只构建文档并打印统计，不写 Meilisearch")
    args = parser.parse_args()

    started = time.monotonic()
    # 本脚本严格只读，不存在“写后查询”一致性需求；局部关闭可避免文档构建
    # 过程中的无意义 autoflush 检查，不改变 Web 请求的默认配置。
    db = SessionLocal(autoflush=False)
    try:
        documents_by_index = build_all_documents(db)
    finally:
        db.close()
    for index_uid, documents in documents_by_index.items():
        _log(f"构建 {index_uid}: {len(documents)} 个文档")

    if args.dry_run:
        for index_uid, documents in documents_by_index.items():
            if documents:
                _log(f"{index_uid} 示例文档: {documents[0]}")
        _log("dry-run 结束，未写入")
        return 0

    client = MeiliClient(settings.MEILISEARCH_URL, settings.MEILISEARCH_KEY, timeout=30.0)
    try:
        if not client.is_healthy():
            _log(f"Meilisearch 不可用: {settings.MEILISEARCH_URL}")
            return 1
        reindex(client, documents_by_index)
    except MeiliError as exc:
        _log(f"重建失败: {exc}")
        return 1
    finally:
        client.close()
    _log(f"完成，总耗时 {time.monotonic() - started:.1f}s")
    return 0


if __name__ == "__main__":
    sys.exit(main())
