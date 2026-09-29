# NCES Next Backend

FastAPI 后端。安装、配置与部署说明见仓库根目录的 [README.md](../README.md)，架构与业务规则见 [AGENTS.md](../AGENTS.md)。

## Run

```bash
cd backend
cp .env.example .env   # 按需填写
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

开发环境下 Swagger UI 位于 `/api/docs`。

## Test

```bash
python -m compileall -q app tests
python -m pytest -q
```
