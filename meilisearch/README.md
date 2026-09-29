# NCES Next 搜索引擎（Meilisearch）

新应用的搜索由 Meilisearch 提供召回与相关性排序；**MySQL 侧全程只读、零新表**，
索引是纯派生数据，可随时删除后秒级重建。后端在引擎不可用时自动回落 SQL 搜索
（`/api/health` 的 `search_engine` 字段：`meilisearch` / `degraded` / `sql`）。

## 架构

```
MySQL(共享库, 只读) ──每5min── backend/scripts/reindex_search.py ──staging──swap──▶ Meilisearch (127.0.0.1:7701)
                                                                                      ▲
用户 ─▶ nginx ─▶ FastAPI /api/v1/search、/api/v1/search/suggest ────ID召回+高亮────────┘
                  └─ 命中 ID 回 MySQL hydrate + filter_reviews_by_visibility 过滤
```

- 三个索引：`courses` / `reviews` / `teachers`（配置见 `backend/app/search/documents.py`）。
- 重建策略：写入 `<name>_staging` → `swap-indexes` 原子切换 → 删 staging。
  失败时线上索引保持原样，脚本非零退出（journald 可见）。
- **安全红线**：`reviews` 索引不存任何作者字段（匿名点评不可能经索引去匿名化）；
  blocked/hidden 点评不进索引；可见性最终一律在 DB hydrate 时强制执行——
  索引滞后只造成相关性偏差，不可能泄露。

## 首次部署

```bash
cd meilisearch
echo "MEILI_MASTER_KEY=$(openssl rand -hex 32)" > .env   # 参考 .env.example
docker-compose up -d
curl http://127.0.0.1:7701/health   # {"status":"available"}

# 后端配置（backend/.env 或 systemd Environment=）：
#   SEARCH_ENGINE=meilisearch
#   MEILISEARCH_KEY=<同上面的 master key>
#   （MEILISEARCH_URL 默认 http://127.0.0.1:7701，通常无需设置）

# 首次建索引（也用于灾备恢复/迁移后重建）：
cd ../backend
python scripts/reindex_search.py

# 定时重建（每 5 分钟）：
sudo cp ../meilisearch/systemd/ncesnext-search-reindex.{service,timer} /etc/systemd/system/
#（部署路径不同时先改 service 里的 WorkingDirectory/ExecStart）
sudo systemctl daemon-reload
sudo systemctl enable --now ncesnext-search-reindex.timer

# 重启后端使 SEARCH_ENGINE 生效，然后验证：
curl http://127.0.0.1:8000/api/health   # search_engine: "meilisearch"
```

## 上线/回滚

- 上线顺序：起容器 → 手动跑一次 reindex → 配置 `SEARCH_ENGINE=meilisearch` 重启后端 → enable timer。
- **回滚只需把 `SEARCH_ENGINE` 改回 `sql`（或删掉该配置）重启后端**；MySQL 从未被写入，无数据风险。
- 引擎临时故障无需操作：每个搜索请求失败时自动回落 SQL 并记 warning 日志。

## 运维

- 备份：**不需要**。`./data` 是派生数据，灾备恢复 = 重跑一次 `reindex_search.py`（约 5 秒）。
- 迁移新机器：拉镜像、拷本目录（`.env` 单独传输）、跑一次 reindex、enable timer。
- 排障：`journalctl -u ncesnext-search-reindex.service -n 50`；
  后端降级日志 grep `Meilisearch 查询失败`；`curl 127.0.0.1:7701/health`。
- 升级 Meilisearch 大版本：数据格式不兼容时直接 `docker-compose down && rm -rf data`，
  改镜像 tag 后 `up -d` 再跑一次 reindex（不用理 dump/升级工具，数据可再生）。
- 新点评在搜索中的可见延迟 = 重建间隔（≤5 分钟），产品预期内。

## 将来接 RAG / hybrid search 的备忘

Meilisearch 已内置向量存储与 hybrid search（embedder 可配 OpenAI/REST/Ollama）。
启用前必须先改重建策略：**staging+swap 全量重建会导致每 5 分钟全量重算 embedding**
（swap 每次从零建索引，享受不到"仅重算变化文档"的 diff 优化）。届时把
`reindex_search.py` 的 writer 层改为就地 upsert + 删除对账（doc builder 层可复用），
并考虑用增量水位表替代全量扫描。查询侧无需变动（hybrid 参数走同一 search API）。
