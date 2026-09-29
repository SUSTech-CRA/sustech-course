import re

# 与老版 app/utils.py:RESERVED_USERNAME 保持一致
RESERVED_USERNAME = {
    "管理员",
    "admin",
    "root",
    "administrator",
    "example",
    "test",
    "匿名",
    "匿名用户",
    "anonymous",
}

_ILLEGAL_CHARS = re.compile(r"[@&<>\"':\s]")


def normalize_username(value: str) -> str:
    return "".join(value.split())


def validate_username_value(username: str) -> str | None:
    """Return an error message when the username is not allowed, otherwise None.

    Mirrors legacy app/utils.py:validate_username (without the DB uniqueness check).
    """
    lowered = username.lower()
    if _ILLEGAL_CHARS.search(lowered):
        return "此用户名含有非法字符，不能注册！"
    if lowered in RESERVED_USERNAME:
        return "此用户名已被保留，不能注册！"
    for reserved in RESERVED_USERNAME:
        if reserved in lowered:
            return "此用户名含有被保留的关键词，不能注册！"
    return None
