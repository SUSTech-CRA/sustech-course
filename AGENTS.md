# AGENTS.md

本文件是 coding agent 在本仓库工作的长期指南。它描述当前架构、不可破坏的业务规则和协作流程。

## 项目现状

NCES 评课社区（南方科技大学课程点评站）的新系统已经成为主要开发目标：后端为 **FastAPI + SQLAlchemy 2 + Pydantic 2**，前端为 **React 19 + TypeScript + Ant Design 6 + Vite 6 SPA**。

老 Flask 单体（本仓库 [`legacy-flask`](https://github.com/SUSTech-CRA/sustech-course/tree/legacy-flask) 分支，源自 [ustc-course](https://github.com/USTC-iCourse/ustc-course)）现已进入准备下线阶段。`ncesnext` 是业务数据的唯一写入方；老系统只需在退役前保留必要的读取能力，不再要求兼容老系统产生的写入，也不要求新功能在老站完整展示。

**内部笔记：** 若工作目录下存在 `.internal/`（维护者私有仓库，已被 `.gitignore` 排除），开始任何任务前先阅读 `.internal/AGENTS.internal.md`，其中包含本机环境、部署拓扑、阶段记录与审查报告。公开贡献者没有该目录，按本文件工作即可。

当前已落地的主要能力包括：单数资源 API、React 19/AntD 6 前端、Cloudflare R2 UGC、Meilisearch 召回与 SQL 自动降级、离线生成的课程公开点评 AI 总结，以及 CKEditor 5 富文本编辑。

## 目录结构

```text
ncesnext/
├── backend/
│   ├── app/
│   │   ├── main.py            # FastAPI 入口 + feed/sitemap/robots/ads
│   │   ├── config.py          # Pydantic Settings；当前仍可回退读取老应用配置
│   │   ├── dependencies.py    # optional/current/active/admin 用户依赖
│   │   ├── core/              # 数据库、安全、限流
│   │   ├── models/            # SQLAlchemy ORM
│   │   ├── schemas/           # Pydantic 请求/响应模型
│   │   ├── api/v1/            # 薄路由层
│   │   ├── services/          # 业务逻辑层
│   │   ├── search/            # Meilisearch 客户端、索引设置与文档构建
│   │   └── utils/             # HTML 清洗、@提及、邮件、图片、用户名等
│   ├── alembic/versions/      # 当前只有 .gitkeep；迁移规则见下文
│   ├── scripts/               # 搜索重建、AI 总结、课程数据与显式 SQL 脚本
│   └── tests/
├── frontend/
│   ├── src/
│   │   ├── api/               # axios；401 刷新与 429 challenge 拦截器
│   │   ├── stores/            # Zustand；认证与 challenge 状态
│   │   ├── components/        # 含 CKEditor、ItemList、HTMLContent 等
│   │   └── hooks/ pages/ types/ utils/
│   └── vite.config.ts         # dev 代理与 vendor 分包
├── meilisearch/               # 容器、systemd 定时重建与部署说明
├── summaries/                 # AI 总结 systemd 与部署说明
├── scripts/nginx/             # edge/backend/dev nginx 配置
├── docs/
└── .internal/                 # 维护者私有笔记（独立 git 仓库，不入库，可能不存在）
```

## 常用命令

后端要求 Python 3.12+，在独立虚拟环境中安装 `backend/requirements.txt`，不要向系统 Python 或老应用环境安装依赖（维护者本机的固定解释器路径见内部笔记）：

```bash
cd backend
python -m compileall -q app tests
python -m pytest -q
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000
```

前端：

```bash
cd frontend
npm run dev                 # 0.0.0.0:8001
npx tsc -b                  # 类型检查
npm run lint
npm run build               # 自带 tsc -b；vendor chunk >500KB 为已知告警
```

开发代理默认指向 `http://127.0.0.1:8000`，可通过 `VITE_DEV_API_ORIGIN` 覆盖。启动新服务前先探测 `curl http://127.0.0.1:8000/api/health`，避免与已有进程冲突。

开发配置连接的可能是真实数据副本，并且 `config.py` 目前仍会回退读取老应用配置（仓库上级目录的 `config/sustech.py` / `config/default.py`，不存在时使用默认值）。不要输出配置或密钥；数据库写入验证必须使用可明确定位的临时数据，并在结束后完全清理。新增配置优先使用 `backend/.env` 或 systemd Environment，不要继续增加对老应用配置的依赖。

## 数据库所有权与老系统退役边界

1. **新系统是唯一写入方。** 不需要处理、轮询或兼容老 Flask 应用产生的新增/修改/删除，也不要为了老系统写入保留双向同步逻辑。部署层应把老系统数据库凭据收敛为只读。老系统代码仅供查阅历史语义，不在本仓库任务中修改。
2. **退役前只保留单向读取兼容。** 未经维护者明确确认下线的老系统读取路径，不能随意删除、重命名或不兼容地改变其依赖的表、列、类型和核心取值语义。新系统写入共享核心实体时，仍应让老系统能读取必要字段；但老 UI 无需支持新功能，也无需保证展示完全一致。
3. **可以做不破坏旧读取的增量演进。** 新系统专用表、列、索引可以按需求引入；改既有结构前必须确认老系统的实际 SELECT 路径、上线顺序、备份和回滚方案。老系统彻底下线后，才可清理只为其读取保留的结构与格式。
4. **不要盲跑 Alembic autogenerate。** 现有 ORM 与生产库存在已知的无害类型差异（如 Text 与 MEDIUMTEXT），自动生成可能产生截断数据的危险迁移。`alembic/versions/` 当前尚无正式迁移；首个迁移或任何 schema 变更都必须显式、最小化并逐条审查，而不是从当前 metadata 生成全库 diff。
5. `course_review_summary` 目前仍按 `backend/scripts/sql/create_course_review_summary.sql` 手工创建；生产步骤见 `summaries/README.md`。不要因为兼容策略放宽就擅自改写既有部署流程。
6. 单向兼容仍涉及老系统会读取的内容：通知的 `ref_class/ref_display_class/display_text`、history operation 取值、`course_rates` 聚合结果和密码哈希格式。密码生成继续显式使用 `pbkdf2:sha256`，直到老站登录读取路径也正式退役。
7. 新 UGC 写入 Cloudflare R2，未配置凭证时返回 503，不回退本地磁盘。`UPLOAD_FOLDER` 与 `/uploads` 挂载只用于读取存量文件；`image_store` 仍记录上传。老站不能正确展示部分绝对 R2 URL 是已经接受的退役期取舍，不要为此恢复双写。

## 关键业务规则

- **点评可见性**由 `review_service.filter_reviews_by_visibility` / `can_view_review` 统一处理：学生看全部非 blocked/hidden 点评；登录非学生看公开点评和自己的点评；游客只看公开点评。blocked/hidden 通常仅作者和管理员可见，但公共 feed（含首页、RSS、搜索索引输入）对作者和管理员也隐藏。
- **匿名点评是隐私红线。** 任何作者维度的查询、列表、搜索、通知、排行、feed 或派生数据都必须考虑 `is_anonymous`。匿名点评通知中的操作者显示“匿名用户”。管理员 API 能看到匿名作者是有意保留的例外。
- **评分归一化**：`(rate_total + avg_rate * avg_rate_count) / (review_count + avg_rate_count)`；课程排序复用 `Course.QUERY_ORDER()`。
- **`course_rates` 是冗余聚合表。** 由新系统的点评创建、更新、删除、屏蔽、隐藏路径调用 `course.update_rate(db, commit_db=False)` 重算。课程评分、课程页统计/学期筛选和贝叶斯排序先验统一排除 blocked/hidden 点评，但 `only_visible_to_student` 点评仍参与课程评分。点评聚合和课程点赞/点踩/关注/加入计数写入前先锁定对应 `course_rates` 行，关系变更后显式 flush 并按数据库事实重算；无需再防御老系统写入造成的聚合变化。
- `SessionLocal` 使用 SQLAlchemy 默认的 `autoflush=True`。需要“先拿聚合锁、后 flush 待写 ORM 状态”的临界区只在 `Course.lock_course_rate()` 内显式使用 `db.no_autoflush`；严格只读的搜索重建脚本实例化 Session 时显式关闭。不要全局关闭 autoflush。评论/点赞/关注等冗余计数必须在父实体行锁内按事实表重算，历史漂移用默认只读的 `backend/scripts/repair_course_rates.py` 审计并显式 `--commit` 回填。
- **学期格式**为 5 位字符串，如 `20242`；末位 `1`=当年秋，`2`=次年春，`3`=次年夏。点评 term 必须属于 `course.term_ids`。
- 每个用户每门课程最多一条点评，由服务层强制。
- 点评四维度各自独立：难度 `[1 简单, 3 困难]`、作业 `[1 不多, 3 超多]`、给分 `[1 超好, 3 杀手]`、收获 `[1 很多, 3 没有]`。后两项也是 1 好、3 差。
- `update_time` 仅在正文或五项评分变化时刷新；只改隐私开关不刷新，以免改变首页排序。
- 富文本写库前必须依次经过 `editor_parse_at()`（转换 @提及并收集通知对象）和 `sanitize()`。前端已发布内容统一用 `HTMLContent` + DOMPurify 渲染；搜索高亮只放行 `mark`。
- 用户名校验统一复用 `utils/username.py`，注册和改名不能各自实现。
- 学号绑定、加入/学过课程和部分历史统计导出已明确废弃，恢复前先与维护者确认。
- 用户主页隐私：`student` 仅本人/管理员可见；隐藏关注关系时关注/粉丝数对他人返回 null；`unread_notification_count` 仅本人返回真实值。

## 搜索、摘要与存储

- 搜索配置为 `SEARCH_ENGINE=sql|meilisearch`。Meilisearch 只负责召回 ID，结果回 MySQL hydrate 并重新经过可见性过滤；引擎异常自动回落 SQL。索引由 `backend/scripts/reindex_search.py` 定时全量重建，部署见 `meilisearch/README.md`。
- 点评索引禁止包含作者字段，blocked/hidden 点评不得入索引；`only_visible_to_student` 必须在查询时预过滤，不能依赖前端隐藏。
- AI 课程总结只由 `backend/scripts/generate_summaries.py` 离线生成，用户请求不得同步调用 LLM。输入只包含游客可见的公开点评且不加载作者字段；输出需通过 schema 与安全规则。部署、隐藏和回滚见 `summaries/README.md`。
- 用户 UGC 使用独立的 `UGC_S3_*` R2 配置；课程资料继续使用独立的 `S3_*` 配置，不要混用桶或凭据。
- 新上传的 JPG/JPEG 大于 `UGC_JPEG_COMPRESS_THRESHOLD_BYTES`（默认 2 MiB）时，在写入 R2 前按原像素尺寸以 `UGC_JPEG_QUALITY`（默认 70）重新编码为 progressive JPEG；不按最长边缩放，以免破坏长截图可读性。压缩不足 10% 时保留原文件，阈值设为 0 可关闭。

## 认证与安全

- JWT access 默认 15 分钟；refresh 默认 2 天，remember 为 14 天。refresh 轮换后用 SHA-256 指纹写入 `revoked_token`。邮箱激活/重置使用一次性 timed token。
- 登录三态：凭据错误 401；未激活 403；`active=False` 停用 403。optional 与强制认证依赖都必须检查 `is_deleted` / `active`。
- CRA SSO state 是带 next 路径的签名 timed token；前端 origin 必须经过白名单。新用户使用随机用户名，不使用 SSO 真实姓名，并自动激活。
- Turnstile 复用 `RECAPTCHA_*` 配置名，覆盖注册、忘记密码和限流 challenge。secret 未配置时验证恒过，只允许开发环境如此。
- API 限流为进程内滑动窗口；生产 4 worker 下实际总配额约为配置值的 4 倍。改 worker 数量时同步评估 `RATE_LIMIT_*`。后端端口不能直接对外，否则不能信任代理写入的 `X-Real-IP`。
- `NCESNEXT_ENV=production` 会关闭默认 API docs、收紧 CORS/OAuth origin，并强制校验 SECRET_KEY 与 Turnstile。显式环境变量优先于派生默认值。

## API 与前端约定

- API JSON 使用 snake_case，路由保持薄，业务逻辑放 services，请求/响应 schema 分离。
- `/api/v1` 的顶层实体前缀使用单数：`/course`、`/review`、`/user`、`/teacher`；子资源集合仍可使用复数。不要重新引入旧的复数 API 前缀。
- 对外页面规范 URL 使用 `/course/:id`、`/teacher/:id`、`/user/:id` 等单数形式。`App.tsx` 中保留的复数页面路由是历史外链/书签别名，未经确认不要删除。
- React 19 使用原生 metadata；列表使用项目的 `ItemList`，不要重新引入 Ant Design 已弃用的 `List`。
- 数字密集内容使用现有 mono 类；颜色改动走 `styles.css` 的 light/dark CSS 变量。CKEditor 编辑态有独立暗色变量，修改编辑器样式时同时检查正文、代码块、表格、占位符与图片说明。
- 时间以 UTC 入库；前端 `format.ts` 将没有时区后缀的 API 时间按 UTC 解析后再转本地。
- 用户可见文案使用中文；后端 `detail` 会直接展示，前端统一通过 `getApiErrorMessage` 取错误。

## 工作流程

- 审查、诊断或方案任务先给出发现和方案；只有用户明确要求修改时才改代码。用户已明确要求实现的任务直接完成并验证。
- **公开与内部的边界。** 本仓库以 AGPLv3 公开。内网地址、主机路径、密钥、尚未公开的审查发现和 agent 沟通记录只能写进 `.internal/`，不得出现在公开文件、代码注释或公开仓库的提交信息中；公开提交信息只描述行为变化本身，不引用内部审查编号。`.internal/` 是独立 git 仓库，其中的改动需在该目录内单独提交。
- 每轮实质性改动后，若存在 `.internal/`，在 `.internal/PHASE_STATUS.md` 末尾追加记录：改动内容、验证命令与结果、遗留人工测试。
- **更新阶段记录时必须同时检查 `AGENTS.md` 与 `.internal/AGENTS.internal.md`。** 如果该阶段改变了当前架构、依赖版本、命令、部署方式、兼容边界、业务规则或工作流程，公开的长期事实同步到本文件，仅限内部的环境、拓扑与待办同步到内部指南；纯历史流水无需复制。
- 审查报告放在 `.internal/reviews/code_review_by_claude_YYYYMMDD.md`；修复后在对应报告末尾追加修复记录。
- 提交信息：标题用具体、简洁的祈使句概括结果，避免只写 `update`、`fix docs` 一类含义过弱的标题；非平凡提交必须有正文，用项目符号说明主要行为变化、关键设计/隐私/兼容取舍、部署或回滚影响以及实际验证结果。正文应解释“改了什么、为什么这样改”，不要只罗列文件名，也不要为了简短省略重要边界。
- 未经实际共同参与或用户明确要求，不要虚构 `Co-Authored-By` trailer。不要改写或清理与当前任务无关的用户改动。
- 验证按影响范围执行；完整基线为后端 `compileall` + `pytest`，前端 `tsc -b` + `lint` + `build`，必要时对真实 uvicorn 做 curl 冒烟。最后运行 `git diff --check`。
