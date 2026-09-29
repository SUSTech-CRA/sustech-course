from app.main import app, health
from app.models import Base


def test_app_imports_and_health_route():
    payload = health()
    assert payload["status"] == "ok"
    assert payload["search_engine"] in {"sql", "meilisearch", "degraded"}
    assert "/api/health" in {getattr(route, "path", "") for route in app.routes}
    assert app.openapi()["info"]["title"] == "NCES API"


def test_auth_models_are_registered():
    expected = {
        "users",
        "students",
        "teachers",
        "depts",
        "dept_classes",
        "majors",
        "revoked_token",
        "third_party_signin_history",
    }
    assert expected.issubset(Base.metadata.tables.keys())


def test_core_models_are_registered():
    expected = {
        "courses",
        "course_rates",
        "course_terms",
        "course_classes",
        "course_time_locations",
        "course_info_history",
        "course_review_summary",
        "reviews",
        "review_comments",
        "review_history",
        "review_comment_history",
        "notifications",
        "image_store",
        "forum_threads",
        "forum_posts",
        "notes",
        "note_comments",
        "shares",
        "share_comments",
        "banner",
        "announcement",
        "search_log",
    }
    assert expected.issubset(Base.metadata.tables.keys())
