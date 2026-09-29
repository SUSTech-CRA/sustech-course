from app.search.documents import (
    HIGHLIGHT_POST,
    HIGHLIGHT_PRE,
    INDEX_REVIEWS,
    INDEX_SETTINGS,
    html_to_text,
)
from app.services.search_service import _format_highlight


def test_html_to_text_strips_tags_and_collapses_whitespace():
    assert html_to_text("<p>第一段</p>\n<p>第二段  内容</p>") == "第一段 第二段 内容"


def test_html_to_text_keeps_inline_tag_continuity():
    # LIKE 版搜不到跨行内标签的词（<b>很</b>好），剥离后必须连续
    assert html_to_text("这门课<b>很</b>好") == "这门课很好"


def test_html_to_text_handles_empty_and_plain_values():
    assert html_to_text(None) == ""
    assert html_to_text("   ") == ""
    assert html_to_text("plain text") == "plain text"


def test_format_highlight_escapes_html_and_replaces_sentinels():
    raw = f"a<b {HIGHLIGHT_PRE}算法{HIGHLIGHT_POST} <script>x</script>"
    formatted = _format_highlight(raw)
    assert formatted == "a&lt;b <mark>算法</mark> &lt;script&gt;x&lt;/script&gt;"


def test_review_index_never_contains_author_fields():
    # 匿名红线：作者维度的字段绝不进点评索引（文档构建端见 build_review_documents）
    searchable = INDEX_SETTINGS[INDEX_REVIEWS]["searchableAttributes"]
    assert not any("author" in attr or "user" in attr for attr in searchable)
    assert "only_visible_to_student" in INDEX_SETTINGS[INDEX_REVIEWS]["filterableAttributes"]
