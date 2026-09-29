import re
from email.utils import format_datetime
from pathlib import Path
from xml.sax.saxutils import escape

from cachelib import SimpleCache
from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import Session

from app.api.v1 import api_router
from app.config import settings
from app.core.database import get_db
from app.core.rate_limit import RateLimitMiddleware
from app.models import Course, Teacher
from app.services.review_service import get_public_feed_reviews


app = FastAPI(
    title="NCES API",
    version="1.0.0",
    docs_url="/api/docs" if settings.API_DOCS_ENABLED else None,
    openapi_url="/api/openapi.json" if settings.API_DOCS_ENABLED else None,
)

# 先于 CORS 添加，使 CORS 成为最外层，429 响应也能带上 CORS 头
app.add_middleware(RateLimitMiddleware)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(api_router, prefix="/api/v1")
app.mount(
    "/uploads",
    StaticFiles(directory=Path(settings.UPLOAD_FOLDER), check_dir=False),
    name="uploads",
)


@app.get("/api/health")
def health() -> dict[str, str]:
    payload = {"status": "ok", "search_engine": "sql"}
    if settings.SEARCH_ENGINE == "meilisearch":
        from app.search.meili_client import get_query_client

        # degraded = 配置了 meilisearch 但探测失败，此时搜索自动回落 SQL 路径
        payload["search_engine"] = "meilisearch" if get_query_client().is_healthy() else "degraded"
    return payload


def _strip_tags(html: str | None) -> str:
    return re.sub(r"<[^>]+>", "", html or "")


@app.get("/feed.xml")
def latest_reviews_feed(db: Session = Depends(get_db)) -> Response:
    site_url = settings.FRONTEND_BASE_URL.rstrip("/")
    items = []
    for review in get_public_feed_reviews(db, limit=100):
        author_name = "匿名用户" if review.is_anonymous or not review.author else review.author.username
        course_name = review.course.name if review.course else ""
        teacher_names = review.course.teacher_names_display if review.course else ""
        title = f"{author_name} 点评了 {course_name}" + (f"（{teacher_names}）" if teacher_names else "")
        link = f"{site_url}/course/{review.course_id}#review-{review.id}"
        description = _strip_tags(review.content)[:150]
        pub_date = format_datetime(review.update_time) if review.update_time else ""
        items.append(
            "<item>"
            f"<title>{escape(title)}</title>"
            f"<link>{escape(link)}</link>"
            f"<pubDate>{pub_date}</pubDate>"
            f"<description>{escape(description)}</description>"
            f"<guid>{escape(link)}</guid>"
            "</item>"
        )
    xml = (
        '<?xml version="1.0" encoding="utf-8"?>\n'
        '<rss version="2.0" xmlns:atom="http://www.w3.org/2005/Atom"><channel>'
        f'<atom:link href="{escape(site_url)}/feed.xml" rel="self" type="application/rss+xml" />'
        "<title>NCES 评课社区 - 全站最新点评</title>"
        f"<link>{escape(site_url)}</link>"
        "<description>评课是为了更好地选课！促进南科大校内课程信息公开，帮助学生找到更适合自己的课程。</description>"
        + "".join(items)
        + "</channel></rss>"
    )
    return Response(content=xml, media_type="application/rss+xml; charset=utf-8")


_sitemap_cache = SimpleCache()


def _build_sitemap_xml(db: Session) -> str:
    site_url = settings.FRONTEND_BASE_URL.rstrip("/")
    static_entries = [
        (f"{site_url}/", "1.0", "daily"),
        (f"{site_url}/courses", "0.8", "daily"),
        (f"{site_url}/rankings", "0.6", "weekly"),
        (f"{site_url}/stats", "0.5", "weekly"),
        (f"{site_url}/about", "0.3", "monthly"),
    ]
    items = [
        f"<url><loc>{escape(loc)}</loc><changefreq>{freq}</changefreq><priority>{priority}</priority></url>"
        for loc, priority, freq in static_entries
    ]
    for (course_id,) in db.query(Course.id).all():
        loc = f"{site_url}/course/{course_id}"
        items.append(f"<url><loc>{escape(loc)}</loc><changefreq>weekly</changefreq><priority>0.7</priority></url>")
    for (teacher_id,) in db.query(Teacher.id).all():
        loc = f"{site_url}/teacher/{teacher_id}"
        items.append(f"<url><loc>{escape(loc)}</loc><changefreq>monthly</changefreq><priority>0.5</priority></url>")
    return (
        '<?xml version="1.0" encoding="utf-8"?>\n'
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">' + "".join(items) + "</urlset>"
    )


@app.get("/sitemap.xml")
def sitemap(db: Session = Depends(get_db)) -> Response:
    xml = _sitemap_cache.get("sitemap")
    if xml is None:
        xml = _build_sitemap_xml(db)
        _sitemap_cache.set("sitemap", xml, timeout=60 * 60)
    return Response(content=xml, media_type="application/xml; charset=utf-8")


@app.get("/ads.txt")
def ads_txt() -> Response:
    # 与 frontend/public/ads.txt 内容一致；双端提供以兼容 nginx 的不同路由方式
    return Response(
        content="google.com, pub-9039393129169217, DIRECT, f08c47fec0942fa0\n",
        media_type="text/plain; charset=utf-8",
    )


@app.get("/robots.txt")
def robots() -> Response:
    site_url = settings.FRONTEND_BASE_URL.rstrip("/")
    content = (
        f"Sitemap: {site_url}/sitemap.xml\n"
        "\n"
        "User-agent: *\n"
        "Disallow: /admin/\n"
        "Disallow: /settings\n"
        "Disallow: /notifications\n"
        "Disallow: /signin\n"
        "Disallow: /signup\n"
        "Disallow: /forgot-password\n"
        "Disallow: /reset-password\n"
        "Disallow: /confirm-email\n"
        "Disallow: /oauth/\n"
        "Disallow: /courses/*/edit\n"
        "Disallow: /course/*/edit\n"
        "Disallow: /courses/*/material\n"
        "Disallow: /course/*/material\n"
        "Disallow: /courses/*/review\n"
        "Disallow: /course/*/review\n"
        "Disallow: /teachers/*/edit\n"
        "Disallow: /teacher/*/edit\n"
        "Disallow: /reviews/*/edit\n"
    )
    return Response(content=content, media_type="text/plain; charset=utf-8")
