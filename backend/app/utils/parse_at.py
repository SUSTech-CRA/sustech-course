import re

from sqlalchemy.orm import Session

from app.models import User


def editor_parse_at(db: Session, text: str) -> tuple[str, set[User]]:
    if not text.endswith("\n"):
        text = text + "\n"

    mentioned_users: set[User] = set()
    non_space = [match.group(1) for match in re.finditer('@([^@<>"\':\\s]+)', text)]
    with_space = [match.group(1) for match in re.finditer('@([^@<>"\':]+)', text)]
    connected = [match.group(1) for match in re.finditer("@([a-zA-Z0-9_.-]+)", text)]

    for username in set(non_space + with_space + connected):
        user = db.query(User).filter(User.username == username).first()
        if user:
            atstring = f'<a href="/user/{user.id}">＠{username}</a>'
            text = re.sub("@" + re.escape(username), atstring, text)
            mentioned_users.add(user)
    return text, mentioned_users
