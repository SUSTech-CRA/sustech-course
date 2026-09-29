from lxml.html.clean import Cleaner


def sanitize(text: str | None) -> str | None:
    if text and text.strip():
        cleaner = Cleaner(safe_attrs_only=False, style=False)
        return cleaner.clean_html(text)
    return text
