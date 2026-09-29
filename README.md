# NCES 评课社区（ncesnext）

NCES（Niuwa Curriculum Evaluation System，牛娃课程评价社区）是面向南方科技大学师生的课程评价社区，线上地址：<https://ncesnext.com>。

本仓库是评课社区的新版系统（ncesnext）：后端使用 Python 3.12 + FastAPI + SQLAlchemy 2 + Pydantic 2，前端使用 React 19 + TypeScript + Ant Design 6 + Vite 构建的单页应用。

## 历史沿革

- [ustc-course](https://github.com/USTC-iCourse/ustc-course)：USTC 评课社区，Python 3 + Flask + SQLAlchemy 开发。
- 本仓库 [`legacy-flask`](https://github.com/SUSTech-CRA/sustech-course/tree/legacy-flask) 分支：在 ustc-course 基础上适配南科大 TIS（课程、教师导入）与 CKEditor 5 等的 Flask 版本，现已停止开发，老站正在下线。
- 本仓库 `master` 分支（ncesnext）：前后端分离重写，沿用原有数据库结构与业务语义。

## ncesnext 相对老系统的主要变化

- 前后端分离：FastAPI 提供 `/api/v1` JSON API，React SPA 负责界面，支持深色模式与移动端布局
- JWT 登录（access / refresh 轮换），南科大 CRA SSO，Cloudflare Turnstile 人机验证
- 应用层按用户 / IP 分键的限流，超限后可通过 Turnstile 自助解封（见 `docs/rate-limiting.md`）
- 用户上传写入 Cloudflare R2 对象存储，大尺寸 JPEG 上传前自动重新压缩
- Meilisearch 搜索召回，引擎不可用时自动回落 SQL 搜索（见 `meilisearch/README.md`）
- 离线生成的课程公开点评 AI 总结，用户请求不会同步调用 LLM（见 `summaries/README.md`）
- CKEditor 5 富文本编辑，服务端 HTML 清洗 + 前端 DOMPurify 渲染

## 安装

安装此系统前，请首先安装：

1. Python 3.12+
2. Node.js 22+
3. MySQL 或 MariaDB（需支持 utf8mb4）
4. Nginx（生产部署）

### 配置和创建数据库

数据库需要使用 utf8mb4 作为默认连接字符集和存储字符集，以免出现乱码，并且支持 emoji。在 MySQL 配置文件（如 `/etc/mysql/my.cnf`）末尾加入如下几行，然后重启数据库：

```
[client]
default-character-set=utf8mb4
[mysql]
default-character-set=utf8mb4
[mysqld]
collation-server = utf8mb4_unicode_ci
init-connect='SET NAMES utf8mb4 COLLATE utf8mb4_unicode_ci'
character-set-server = utf8mb4
```

`mysql -u root -p` 进入 MySQL 控制台，创建数据库和用户（生产环境上请换用强密码）：

```sql
CREATE DATABASE icourse;
CREATE USER 'ncesnext'@'localhost' IDENTIFIED BY 'ncesnext';
GRANT ALL ON icourse.* TO 'ncesnext'@'localhost';
```

数据库结构沿用老系统。从老系统迁移时直接连接原有数据库即可；全新部署或本地开发可以由 ORM 建表：

```bash
cd backend
python -c "from app.core.database import engine; from app.models import Base; Base.metadata.create_all(engine)"
```

注意：仓库目前没有正式的 Alembic 迁移，**不要**对已有数据库运行 `alembic revision --autogenerate`。ORM 声明与老库之间存在无害的类型差异（如 Text 与 MEDIUMTEXT），自动生成的迁移可能截断数据。结构变更请手写最小化 SQL 并逐条审查。

### 后端

```bash
cd backend
python3.12 -m venv ../.venv
../.venv/bin/pip install -r requirements.txt   # mysqlclient 需要系统先装 MySQL 客户端开发库与 pkg-config
cp .env.example .env    # 按下文说明填写
```

后端配置由 `backend/app/config.py` 读取，可以写在 `backend/.env` 中，也可以通过 systemd `Environment=` 注入。`backend/.env.example` 列出了常用配置项：

* `NCESNEXT_ENV` 设为 `production` 时会关闭 API 文档、收紧 CORS，并强制检查 `SECRET_KEY` 与 Turnstile 是否已配置。
* `SECRET_KEY` 用于签发 JWT、邮件激活链接、OAuth state 和限流豁免凭证，填入一个足够长的随机字符串（如 `openssl rand -hex 32`）。
* `DATABASE_URL` 是数据库连接信息，格式为 `mysql+mysqldb://用户名:密码@数据库地址/数据库名?charset=utf8mb4`。
* `MAIL_*` 是外发邮件（注册激活、找回密码）的发件配置。
* `RECAPTCHA_SITE_KEY` / `RECAPTCHA_SECRET_KEY` 实际填写 Cloudflare Turnstile 的密钥（名字是历史遗留）。未配置时验证恒通过，只允许在开发环境这样做。
* `UGC_S3_*` 是用户上传使用的 R2 / S3 兼容公开桶；未配置时上传接口返回 503。
* `UPLOAD_FOLDER` 是老系统存量上传文件所在的目录，仅用于读取。
* `CORS_ORIGINS` 是允许的前端 origin（JSON 数组），默认值按 `NCESNEXT_ENV` 派生。

兼容说明：从老系统迁移时，`config.py` 会在未设置对应环境变量时回退读取仓库上级目录的 `config/sustech.py` / `config/default.py`。全新部署无需理会，直接使用环境变量即可。

启动开发服务器：

```bash
cd backend
../.venv/bin/python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
curl http://127.0.0.1:8000/api/health
```

开发环境下 Swagger UI 位于 `/api/docs`。

### 前端

```bash
cd frontend
npm ci
npm run dev      # http://localhost:8001，/api 等路径代理到 http://127.0.0.1:8000
npm run build    # 产物在 frontend/dist
```

后端不在本机时，用环境变量指定代理目标：`VITE_DEV_API_ORIGIN=http://<后端地址>:8000 npm run dev`。

Sentry、Google Analytics、AdSense 均为可选的构建期配置，未配置时不会加载，见 `frontend/.env.example`。`frontend/public/ads.txt` 是本站的 AdSense 声明，自行部署时请替换或删除（后端 `app/main.py` 中也有同名路由）。

### 配置 Nginx

生产部署推荐“公网边缘机 + 后端机”两层 nginx，也可以单机部署。示例配置和说明见 `scripts/nginx/README.md`。

生产环境用多个 worker 运行 uvicorn，并且只监听本机或内网地址：

```bash
../.venv/bin/python -m uvicorn app.main:app --host 127.0.0.1 --port 3001 --workers 4
```

后端信任 nginx 写入的 `X-Real-IP` 做限流与审计，**uvicorn 端口绝不能直接对公网开放**。限流计数器在进程内，全局配额约为配置值乘以 worker 数，调整 worker 数时请同步评估 `RATE_LIMIT_*`。

### 可选组件

* 搜索引擎：`meilisearch/README.md`（Docker 运行 Meilisearch，systemd timer 定时全量重建索引）。
* AI 课程总结：`summaries/README.md`（需要先执行 `backend/scripts/sql/create_course_review_summary.sql` 建表）。
* 课程数据导入：`backend/scripts/` 下的 `import_sustech_courses.py`、`merge_*`、`update_course_catalog_metadata.py`、`download_course_syllabi.py`，用于从南科大教务系统导出的数据导入课程与教学大纲。各脚本的 `--help` 有详细说明。
* 聚合数据修复：`backend/scripts/repair_course_rates.py` 默认只读审计课程评分等冗余计数，确认后加 `--commit` 回填。

## 开发

系统的主要文件：

* `backend/app/api/v1` 是薄路由层
* `backend/app/services` 是业务逻辑
* `backend/app/models` 是 ORM 类，`backend/app/schemas` 是 Pydantic 请求/响应模型
* `backend/app/search` 是 Meilisearch 客户端与索引文档构建
* `backend/app/utils` 是 HTML 清洗、@提及、邮件、图片等工具函数
* `frontend/src` 是 React 前端，`pages` 为页面，`components` 为组件，`api` 为请求封装

架构说明、不可破坏的业务规则（点评可见性、匿名隐私、评分归一化等）和协作约定见 [`AGENTS.md`](AGENTS.md)，提交代码前请先阅读。

提交前的验证基线：

```bash
cd backend && python -m compileall -q app tests && python -m pytest -q
cd frontend && npx tsc -b && npm run lint && npm run build
git diff --check
```

## 安全问题

发现安全漏洞时请不要公开提交 issue，报告方式见 [`SECURITY.md`](SECURITY.md)。

## License

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
