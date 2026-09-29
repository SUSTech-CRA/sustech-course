from __future__ import annotations

import importlib.util
import os
import sys
import warnings
from functools import lru_cache
from pathlib import Path
from typing import Any, Literal

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


def _legacy_config_value(name: str, default: Any = None) -> Any:
    """Read existing Flask config without printing secrets or importing the old app."""
    root = Path(__file__).resolve().parents[3]
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))
    for module_name in ("config.sustech", "config.default"):
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", SyntaxWarning)
                module = __import__(module_name, fromlist=["*"])
        except Exception:
            continue
        if hasattr(module, name):
            return getattr(module, name)
    for filename in ("sustech.py", "default.py"):
        path = root / "config" / filename
        if not path.exists():
            continue
        spec = importlib.util.spec_from_file_location(f"_nces_legacy_{filename}", path)
        if spec is None or spec.loader is None:
            continue
        module = importlib.util.module_from_spec(spec)
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", SyntaxWarning)
            spec.loader.exec_module(module)
        if hasattr(module, name):
            return getattr(module, name)
    return default


def _legacy_oauth_value(name: str, default: str = "") -> str:
    oauth = _legacy_config_value("OAUTH", {}) or {}
    return oauth.get(name, default) or default


def _oauth_redirect_uri() -> str:
    env_value = os.getenv("OAUTH_REDIRECT_URI")
    if env_value:
        return env_value
    legacy_value = _legacy_oauth_value("redirect_uri")
    if legacy_value and "/login/oauth/callback" not in legacy_value:
        return legacy_value
    return "https://ncesnext.com/api/v1/auth/oauth/cra/callback"


def _legacy_mail_from() -> str:
    return _legacy_config_value("MAIL_DEFAULT_SENDER", "support@icourse.club")


# CORS / OAuth 回跳 origin 白名单按环境派生的默认值；
# 换域名时无需改代码，用环境变量 CORS_ORIGINS（JSON 数组）覆盖即可
_PROD_CORS_ORIGINS = [
    "https://ncesnext.com",
    "https://ncesnext.com",
]
_DEV_CORS_ORIGINS = [
    "http://localhost:8001",
    "https://localhost:8001",
    "http://127.0.0.1:8001",
    "http://dev.ncesnext.com",
    "https://dev.ncesnext.com",
    "http://dev.ncesnext.com:8001",
    "https://dev.ncesnext.com:8001",
    *_PROD_CORS_ORIGINS,
]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # 环境开关：production 收紧各开关的默认值并启用启动强制校验。
    # 未设置时默认 development；取值必须是这两个字面量，拼错会在启动时报错。
    NCESNEXT_ENV: Literal["development", "production"] = "development"

    DEBUG: bool = Field(default_factory=lambda: bool(_legacy_config_value("DEBUG", False)))
    SECRET_KEY: str = Field(default_factory=lambda: _legacy_config_value("SECRET_KEY", "dev-secret-key"))
    SERVER_NAME: str | None = Field(default_factory=lambda: _legacy_config_value("SERVER_NAME", None))

    DATABASE_URL: str = Field(
        default_factory=lambda: os.getenv(
            "SQLALCHEMY_DATABASE_URI",
            _legacy_config_value(
                "SQLALCHEMY_DATABASE_URI",
                "mysql+mysqldb://user:pass@localhost/icourse?charset=utf8mb4",
            ),
        )
    )

    ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    REFRESH_TOKEN_EXPIRE_DAYS: int = 2
    REMEMBER_REFRESH_TOKEN_EXPIRE_DAYS: int = 14
    JWT_ALGORITHM: str = "HS256"
    EMAIL_TOKEN_EXPIRE_SECONDS: int = 24 * 60 * 60

    MAIL_SERVER: str = Field(default_factory=lambda: _legacy_config_value("MAIL_SERVER", "localhost"))
    MAIL_PORT: int = Field(default_factory=lambda: int(_legacy_config_value("MAIL_PORT", 25) or 25))
    MAIL_USERNAME: str | None = Field(default_factory=lambda: _legacy_config_value("MAIL_USERNAME", None))
    MAIL_PASSWORD: str | None = Field(default_factory=lambda: _legacy_config_value("MAIL_PASSWORD", None))
    MAIL_FROM: str = Field(default_factory=_legacy_mail_from)
    MAIL_USE_TLS: bool = Field(default_factory=lambda: bool(_legacy_config_value("MAIL_USE_TLS", False)))
    MAIL_USE_SSL: bool = Field(default_factory=lambda: bool(_legacy_config_value("MAIL_USE_SSL", False)))
    MAIL_SUPPRESS_SEND: bool = False

    # 搜索引擎：sql = 直接查 MySQL（默认，零外部依赖）；
    # meilisearch = Meilisearch 只做 ID 召回，回 MySQL hydrate 并复用可见性过滤，
    # 引擎请求失败时自动回落 SQL 路径（见 services/search_service.py）。
    # 索引由 backend/scripts/reindex_search.py 定时全量重建，MySQL 侧永远只读。
    SEARCH_ENGINE: Literal["sql", "meilisearch"] = "sql"
    # 新实例（meilisearch/docker-compose.yml）固定绑 127.0.0.1:7701；
    # 7700 是老应用当年的实例，勿混用
    MEILISEARCH_URL: str = "http://127.0.0.1:7701"
    MEILISEARCH_KEY: str = ""
    MEILISEARCH_TIMEOUT_SECONDS: float = 1.5

    # 课程公开点评 AI 总结。只有离线脚本使用这些配置；API 请求本身绝不调用 LLM。
    # LLM_API_KEY 为空时生成任务直接正常退出，现有站点功能不受影响。
    LLM_BASE_URL: str = "https://api.deepseek.com"
    LLM_API_KEY: str = ""
    LLM_MODEL: str = "deepseek-v4-pro"
    LLM_TIMEOUT_SECONDS: float = 180.0
    COURSE_SUMMARY_MIN_PUBLIC_REVIEWS: int = 10

    S3_ENDPOINT_URL: str = ""
    S3_ACCESS_KEY: str = ""
    S3_SECRET_KEY: str = ""
    S3_BUCKET_NAME: str = ""

    # UGC 公开对象存储（Cloudflare R2 独立公开桶）：用户上传的图片/附件/头像。
    # 与上面的课程资料桶（S3_*）互相独立；凭证只需此桶的写权限，公开读走自定义域。
    # 部署时在 backend/.env 或 systemd Environment 填写：
    #   UGC_S3_ENDPOINT_URL=https://<account_id>.r2.cloudflarestorage.com
    #   UGC_S3_ACCESS_KEY=<access key id>
    #   UGC_S3_SECRET_KEY=<secret access key>
    # 未配置凭证时上传接口返回 503，不回退写本地磁盘。
    UGC_S3_ENDPOINT_URL: str = ""
    UGC_S3_ACCESS_KEY: str = ""
    UGC_S3_SECRET_KEY: str = ""
    UGC_S3_BUCKET_NAME: str = "nces-ugc-public-content"
    UGC_S3_PUBLIC_BASE_URL: str = "https://nces-ugcdata.ncesnext.com"
    # 大 JPEG 在上传 R2 前原尺寸重新编码；阈值设为 0 可关闭。
    UGC_JPEG_COMPRESS_THRESHOLD_BYTES: int = Field(default=2 * 1024 * 1024, ge=0)
    UGC_JPEG_QUALITY: int = Field(default=70, ge=1, le=95)

    OAUTH_CLIENT_ID: str = Field(default_factory=lambda: _legacy_oauth_value("client_id"))
    OAUTH_CLIENT_SECRET: str = Field(default_factory=lambda: _legacy_oauth_value("client_secret"))
    OAUTH_REDIRECT_URI: str = Field(default_factory=_oauth_redirect_uri)
    OAUTH_AUTH_URL: str = Field(default_factory=lambda: _legacy_oauth_value("auth_url"))
    OAUTH_TOKEN_URL: str = Field(default_factory=lambda: _legacy_oauth_value("token_url"))
    OAUTH_API_URL: str = Field(default_factory=lambda: _legacy_oauth_value("api_url"))
    OAUTH_SCOPE: str = Field(default_factory=lambda: _legacy_oauth_value("scope", "profile"))

    RATE_LIMIT_ENABLED: bool = True
    # 计数器是进程内的，全局上限 ≈ 配置值 × uvicorn worker 数。
    # 以下默认值按生产 4 worker 校准（实际生效大约*4）。
    RATE_LIMIT_ANON_PER_MINUTE: int = 20
    RATE_LIMIT_USER_PER_MINUTE: int = 60
    RATE_LIMIT_WRITE_PER_MINUTE: int = 8
    # 搜索建议（search-as-you-type）独立配额，不占用通用配额；
    # 前端有 debounce，正常输入每个查询词约消耗 2~4 次
    RATE_LIMIT_SUGGEST_PER_MINUTE: int = 40
    RATE_LIMIT_CHALLENGE_ENABLED: bool = True
    RATE_LIMIT_EXEMPT_MINUTES: int = 20

    # 短期写入审计：用于共库过渡期识别通过新系统完成内容写入的用户。
    # 默认关闭；开启后写 JSONL 文件，不改变共用数据库结构。
    WRITE_AUDIT_ENABLED: bool = True
    WRITE_AUDIT_PATH: str = "/var/log/ncesnext/write_audit.jsonl"

    RECAPTCHA_SITE_KEY: str = Field(
        default_factory=lambda: _legacy_config_value("RECAPTCHA_SITE_KEY", "")
    )
    RECAPTCHA_SECRET_KEY: str = Field(
        default_factory=lambda: _legacy_config_value("RECAPTCHA_SECRET_KEY", "")
    )
    TURNSTILE_VERIFY_URL: str = "https://challenges.cloudflare.com/turnstile/v0/siteverify"

    UPLOAD_FOLDER: str = Field(
        default_factory=lambda: _legacy_config_value("UPLOAD_FOLDER", "/srv/ustc-course/uploads")
    )
    # 不读老配置：白名单收紧后（去掉 xml 等可承载脚本的类型）在新应用内固定
    ALLOWED_EXTENSIONS: dict[str, set[str]] = Field(
        default_factory=lambda: {
            "image": {"png", "jpg", "jpeg", "gif"},
            "file": set(
                "7z|avi|csv|doc|docx|flv|gif|gz|gzip|jpeg|jpg|mov|mp3|mp4|mpc|mpeg|mpg|ods|odt|pdf|png|ppt|pptx|ps|pxd|rar|rtf|tar|tgz|txt|vsd|wav|wma|wmv|xls|xlsx|zip".split(
                    "|"
                )
            ),
        }
    )
    MAX_CONTENT_LENGTH: int = Field(
        default_factory=lambda: int(_legacy_config_value("MAX_CONTENT_LENGTH", 100 * 1024 * 1024) or 0)
    )

    FRONTEND_BASE_URL: str = Field(
        default_factory=lambda: _legacy_config_value("FRONTEND_BASE_URL", "https://ncesnext.com")
    )
    API_BASE_URL: str = "http://localhost:8000"
    # None 表示按 NCESNEXT_ENV 派生默认值（development 开、production 关）；显式设置仍优先
    API_DOCS_ENABLED: bool | None = None
    # None 表示按 NCESNEXT_ENV 派生默认值；显式设置（JSON 数组）仍优先
    CORS_ORIGINS: list[str] | None = None

    @property
    def is_production(self) -> bool:
        return self.NCESNEXT_ENV == "production"

    @model_validator(mode="after")
    def _apply_environment_defaults_and_checks(self) -> "Settings":
        if self.API_DOCS_ENABLED is None:
            self.API_DOCS_ENABLED = not self.is_production
        if self.CORS_ORIGINS is None:
            self.CORS_ORIGINS = list(_PROD_CORS_ORIGINS if self.is_production else _DEV_CORS_ORIGINS)
        # SECRET_KEY 同时签发 JWT/邮箱令牌/限流豁免票/OAuth state，
        # 回退到公开的开发默认值时绝不能在生产（或非 DEBUG）环境启动
        if self.SECRET_KEY == "dev-secret-key" and (self.is_production or not self.DEBUG):
            raise RuntimeError(
                "SECRET_KEY 未配置（读取老应用 config 失败且未设置环境变量）。"
                "生产环境禁止使用默认开发密钥，请设置 SECRET_KEY 后再启动。"
            )
        # Turnstile secret 缺失时 verify_turnstile 恒过：注册无验证码、限流 challenge 免费发豁免票，
        # 生产环境必须配置
        if self.is_production and not (self.RECAPTCHA_SECRET_KEY and self.RECAPTCHA_SITE_KEY):
            raise RuntimeError(
                "生产环境必须配置 Cloudflare Turnstile（RECAPTCHA_SITE_KEY / RECAPTCHA_SECRET_KEY），"
                "否则注册与限流 challenge 将无人机验证。"
            )
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
