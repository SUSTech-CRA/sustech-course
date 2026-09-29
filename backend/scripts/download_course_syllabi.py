#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import random
import re
import sys
import time
import zipfile
from dataclasses import dataclass, asdict
from email.message import Message
from email.parser import Parser
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Any, Iterable

import requests
from lxml import html


CAS_URL = "https://cas.sustech.edu.cn/cas/login?service=https%3A%2F%2Ftis.sustech.edu.cn%2Fcas"
DOWNLOAD_URL = "https://tis.sustech.edu.cn/kck/kcxxwh/downFj"
REFERER_URL = "https://tis.sustech.edu.cn/kck/kcxxwh/getXsck"

CONTENT_TYPE_EXTENSIONS = {
    "application/pdf": "pdf",
    "application/msword": "doc",
    "application/vnd.ms-word": "doc",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document": "docx",
    "application/vnd.ms-excel": "xls",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": "xlsx",
    "application/vnd.ms-powerpoint": "ppt",
    "application/vnd.openxmlformats-officedocument.presentationml.presentation": "pptx",
    "text/html": "html",
}

KNOWN_OUTPUT_EXTENSIONS = ("pdf", "docx", "doc", "pptx", "ppt", "xlsx", "xls", "zip", "bin")

SYLLABUS_LANGUAGES = {
    "zh": ("kczwdgurl", "zwfj"),
    "en": ("kcywdgurl", "ywfj"),
}


@dataclass(frozen=True)
class DownloadTask:
    course_code: str
    course_name: str
    kcid: str
    language: str
    url_field: str
    fjflag: str


@dataclass
class ManifestRow:
    course_code: str
    course_name: str
    kcid: str
    language: str
    fjflag: str
    url_field: str
    status: str
    http_status: int | None = None
    content_type: str | None = None
    content_disposition: str | None = None
    response_filename: str | None = None
    detected_extension: str | None = None
    output_path: str | None = None
    size: int | None = None
    sha256: str | None = None
    error: str | None = None


def clean_text(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    if not text or text.lower() in {"none", "null"}:
        return None
    return text


def safe_stem(value: str, *, fallback: str = "course") -> str:
    stem = re.sub(r"[^\w.-]+", "_", value.strip(), flags=re.ASCII).strip("._")
    return stem or fallback


def load_catalog_rows(path: Path) -> tuple[list[dict[str, Any]], int | None]:
    with path.open(encoding="utf-8") as handle:
        payload = json.load(handle)

    if isinstance(payload, dict):
        declared_total = payload.get("total") if isinstance(payload.get("total"), int) else None
        for key in ("list", "data", "rows"):
            rows = payload.get(key)
            if isinstance(rows, list):
                return rows, declared_total
        raise ValueError(f"{path} does not contain a list/data/rows array")

    if isinstance(payload, list):
        if all(isinstance(item, dict) and isinstance(item.get("list"), list) for item in payload):
            rows: list[dict[str, Any]] = []
            total = 0
            for page in payload:
                rows.extend(page["list"])
                if isinstance(page.get("total"), int):
                    total = max(total, page["total"])
            return rows, total or None
        return payload, None

    raise ValueError(f"{path} has unsupported JSON shape")


def selected_languages(value: str) -> list[str]:
    if value == "both":
        return ["zh", "en"]
    return [value]


def iter_tasks(rows: Iterable[dict[str, Any]], languages: list[str]) -> list[DownloadTask]:
    tasks: list[DownloadTask] = []
    seen: set[tuple[str, str]] = set()
    for row in rows:
        kcid = clean_text(row.get("kcid"))
        course_code = clean_text(row.get("kcdm"))
        if not kcid or not course_code:
            continue
        course_name = clean_text(row.get("kcmc")) or ""
        for language in languages:
            url_field, fjflag = SYLLABUS_LANGUAGES[language]
            if not clean_text(row.get(url_field)):
                continue
            key = (kcid, fjflag)
            if key in seen:
                continue
            seen.add(key)
            tasks.append(
                DownloadTask(
                    course_code=course_code.replace(".", "").upper(),
                    course_name=course_name,
                    kcid=kcid,
                    language=language,
                    url_field=url_field,
                    fjflag=fjflag,
                )
            )
    return tasks


def configure_session(args: argparse.Namespace) -> requests.Session:
    session = requests.Session()
    session.headers.update(
        {
            "User-Agent": args.user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,application/pdf,*/*;q=0.8",
            "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
            "Cache-Control": "no-cache",
            "Pragma": "no-cache",
            "Referer": REFERER_URL,
        }
    )
    cookie = args.cookie or read_cookie_file(args.cookie_file)
    if cookie:
        session.headers["Cookie"] = cookie
    if args.username:
        password = args.password or (os.getenv(args.password_env) if args.password_env else None)
        if not password:
            raise ValueError("Password is required when --username is used")
        cas_login(session, args.username, password)
    return session


def read_cookie_file(path: Path | None) -> str | None:
    if path is None:
        return None
    text = path.read_text(encoding="utf-8").strip()
    if not text:
        return None
    if text.lower().startswith("cookie:"):
        return text.split(":", 1)[1].strip()
    return text


def cas_login(session: requests.Session, username: str, password: str) -> None:
    response = session.get(CAS_URL, timeout=20)
    response.raise_for_status()
    tree = html.fromstring(response.text)
    execution_values = tree.xpath('//input[@name="execution"]/@value')
    if not execution_values:
        raise RuntimeError("CAS login page did not include an execution token")
    data = {
        "username": username,
        "password": password,
        "execution": execution_values[0],
        "_eventId": "submit",
        "geolocation": "",
    }
    result = session.post(CAS_URL, data=data, timeout=20, allow_redirects=True)
    result.raise_for_status()
    lowered = result.text.lower()
    if "alert-danger" in lowered or "password" in lowered and "login" in lowered:
        raise RuntimeError("CAS login appears to have failed")


def parse_content_disposition(value: str | None) -> tuple[str | None, str | None]:
    if not value:
        return None, None
    message: Message = Parser().parsestr(f"Content-Disposition: {value}\n")
    filename = message.get_filename()
    if not filename:
        return None, None
    filename = Path(filename).name
    suffix = Path(filename).suffix.lower().lstrip(".") or None
    return filename, suffix


def detect_extension(content: bytes, content_type: str | None, filename_ext: str | None) -> str:
    if content.startswith(b"%PDF-"):
        return "pdf"
    if content.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        ole_ext = detect_ole_office_extension(content)
        if ole_ext:
            return ole_ext
        return filename_ext if filename_ext in {"doc", "xls", "ppt"} else "doc"
    if content.startswith(b"PK\x03\x04"):
        zip_ext = detect_zip_office_extension(content)
        if zip_ext:
            return zip_ext
        return filename_ext if filename_ext else "zip"
    if content.lstrip().lower().startswith((b"<!doctype html", b"<html")):
        return "html"
    normalized_type = (content_type or "").split(";", 1)[0].strip().lower()
    if normalized_type in CONTENT_TYPE_EXTENSIONS:
        return CONTENT_TYPE_EXTENSIONS[normalized_type]
    return filename_ext or "bin"


def detect_ole_office_extension(content: bytes) -> str | None:
    # The TIS endpoint often lies via Content-Type, so keep these ugly
    # legacy Office markers as a pragmatic second pass after OLE magic bytes.
    if b"\xec\xa5\xc1\x00" in content:
        return "doc"
    if b"\xfd\xff\xff\xff" in content:
        return "xls"
    if b"\xa0\x46\x1d\xf0" in content:
        return "ppt"
    return None


def detect_zip_office_extension(content: bytes) -> str | None:
    try:
        from io import BytesIO

        with zipfile.ZipFile(BytesIO(content)) as archive:
            names = set(archive.namelist())
    except zipfile.BadZipFile:
        return None
    if any(name.startswith("word/") for name in names):
        return "docx"
    if any(name.startswith("ppt/") for name in names):
        return "pptx"
    if any(name.startswith("xl/") for name in names):
        return "xlsx"
    return None


def output_path_for(task: DownloadTask, output_dir: Path, extension: str) -> Path:
    stem = safe_stem(task.course_code)
    if task.language != "zh":
        stem = f"{stem}.{task.language}"
    return output_dir / f"{stem}.{extension}"


def existing_output_for(task: DownloadTask, output_dir: Path) -> Path | None:
    for extension in KNOWN_OUTPUT_EXTENSIONS:
        candidate = output_path_for(task, output_dir, extension)
        if candidate.exists():
            return candidate
    stem = safe_stem(task.course_code)
    if task.language != "zh":
        stem = f"{stem}.{task.language}"
    matches = sorted(output_dir.glob(f"{stem}.*"))
    return matches[0] if matches else None


def download_task(
    session: requests.Session,
    task: DownloadTask,
    output_dir: Path,
    *,
    timeout: float,
    retries: int,
    force: bool,
    method: str,
) -> ManifestRow:
    row = ManifestRow(
        course_code=task.course_code,
        course_name=task.course_name,
        kcid=task.kcid,
        language=task.language,
        fjflag=task.fjflag,
        url_field=task.url_field,
        status="pending",
    )

    if not force:
        existing = existing_output_for(task, output_dir)
        if existing is not None:
            row.status = "skipped_existing"
            row.output_path = str(existing)
            row.detected_extension = existing.suffix.lower().lstrip(".") or None
            row.size = existing.stat().st_size
            row.sha256 = sha256_file(existing)
            return row

    params = {"kcid": task.kcid, "fjflag": task.fjflag, "downFlag": ""}
    last_error: str | None = None
    for attempt in range(retries + 1):
        try:
            response = session.request(
                method,
                DOWNLOAD_URL,
                params=params,
                timeout=timeout,
                allow_redirects=True,
            )
            row.http_status = response.status_code
            row.content_type = response.headers.get("Content-Type")
            row.content_disposition = response.headers.get("Content-Disposition")
            if response.status_code != 200:
                row.status = "http_error"
                row.error = f"HTTP {response.status_code}"
                return row

            filename, filename_ext = parse_content_disposition(row.content_disposition)
            row.response_filename = filename
            extension = detect_extension(response.content, row.content_type, filename_ext)
            row.detected_extension = extension

            if extension == "html":
                row.status = "login_or_empty_html"
                row.error = "Server returned HTML; cookie/session may be expired or no file is available"
                return row

            target = output_path_for(task, output_dir, extension)
            row.output_path = str(target)
            if target.exists() and not force:
                row.status = "skipped_existing"
                row.size = target.stat().st_size
                row.sha256 = sha256_file(target)
                return row

            target.parent.mkdir(parents=True, exist_ok=True)
            with NamedTemporaryFile("wb", delete=False, dir=target.parent, prefix=f".{target.name}.") as tmp:
                tmp.write(response.content)
                tmp_path = Path(tmp.name)
            tmp_path.replace(target)

            row.status = "downloaded"
            row.size = len(response.content)
            row.sha256 = hashlib.sha256(response.content).hexdigest()
            return row
        except (requests.RequestException, OSError) as exc:
            last_error = str(exc)
            if attempt >= retries:
                break
            time.sleep(min(2**attempt, 10))

    row.status = "error"
    row.error = last_error or "unknown error"
    return row


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_manifest_row(path: Path, row: ManifestRow) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(asdict(row), ensure_ascii=False, sort_keys=True) + "\n")


def print_summary(rows: list[ManifestRow], total_tasks: int, skipped_without_url: int) -> None:
    counts = Counter(row.status for row in rows)
    ext_counts = Counter(row.detected_extension for row in rows if row.detected_extension)
    print("\nSyllabus download summary")
    print(f"  tasks: {total_tasks}")
    print(f"  skipped rows without selected syllabus URL: {skipped_without_url}")
    print(f"  statuses: {dict(counts)}")
    print(f"  detected extensions: {dict(ext_counts)}")
    non_pdf = [row for row in rows if row.detected_extension and row.detected_extension != "pdf"]
    if non_pdf:
        print("  non-PDF examples:")
        for row in non_pdf[:12]:
            print(f"    - {row.course_code} {row.language}: .{row.detected_extension} ({row.status})")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Download SUSTech course syllabus attachments from catalog JSON.")
    parser.add_argument("catalog_json", type=Path, help="Catalog JSON with list/data/rows or a list of rows/pages")
    parser.add_argument("--output-dir", type=Path, default=Path("course-syllabi"), help="Destination directory")
    parser.add_argument(
        "--manifest",
        type=Path,
        default=None,
        help="JSONL manifest path. Default: <output-dir>/download_manifest.jsonl",
    )
    parser.add_argument("--language", choices=["zh", "en", "both"], default="zh", help="Which syllabus attachment to download")
    parser.add_argument("--cookie", help="Raw Cookie header copied from the browser")
    parser.add_argument("--cookie-file", type=Path, help="Text file containing a raw Cookie header")
    parser.add_argument("--username", help="CAS username. Cookie auth is usually more reliable.")
    parser.add_argument("--password", help="CAS password. Prefer --password-env.")
    parser.add_argument("--password-env", default="SUSTECH_CAS_PASSWORD", help="Env var for CAS password")
    parser.add_argument("--method", choices=["GET", "POST"], default="GET", help="Endpoint method; the browser curl usually works as GET")
    parser.add_argument("--timeout", type=float, default=30.0)
    parser.add_argument("--retries", type=int, default=2)
    parser.add_argument("--delay-min", type=float, default=1.0)
    parser.add_argument("--delay-max", type=float, default=2.5)
    parser.add_argument("--start-row", type=int, default=0, help="Skip the first N catalog rows before planning tasks")
    parser.add_argument("--start-task", type=int, default=0, help="Skip the first N planned download tasks")
    parser.add_argument("--limit", type=int, help="Download at most N tasks")
    parser.add_argument("--force", action="store_true", help="Overwrite existing files")
    parser.add_argument("--dry-run", action="store_true", help="List planned tasks without downloading")
    parser.add_argument(
        "--continue-on-login-html",
        action="store_true",
        help="Keep going if TIS returns HTML, which usually means the session expired",
    )
    parser.add_argument(
        "--user-agent",
        default="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if not args.catalog_json.exists():
        print(f"Missing input file: {args.catalog_json}", file=sys.stderr)
        return 2
    if args.delay_max < args.delay_min:
        raise ValueError("--delay-max must be >= --delay-min")

    rows, declared_total = load_catalog_rows(args.catalog_json)
    original_row_count = len(rows)
    if args.start_row < 0 or args.start_task < 0:
        raise ValueError("--start-row and --start-task must be non-negative")
    if args.start_row:
        rows = rows[args.start_row :]
    languages = selected_languages(args.language)
    tasks = iter_tasks(rows, languages)
    skipped_without_url = len(rows) * len(languages) - len(tasks)
    original_task_count = len(tasks)
    if args.start_task:
        tasks = tasks[args.start_task :]
    if args.limit is not None:
        tasks = tasks[: args.limit]

    if declared_total is not None and declared_total > original_row_count:
        print(f"Warning: JSON declares total={declared_total}, but contains {original_row_count} row(s).")
    print(f"Catalog rows: {original_row_count}")
    if args.start_row:
        print(f"Start row: {args.start_row}; remaining rows considered: {len(rows)}")
    if args.start_task:
        print(f"Start task: {args.start_task}; planned before task skip: {original_task_count}")
    print(f"Planned download tasks: {len(tasks)}")
    print(f"Rows/language slots without selected syllabus URL: {skipped_without_url}")

    if args.dry_run:
        for task in tasks[:50]:
            print(f"{task.course_code}\t{task.language}\t{task.kcid}\t{task.course_name}")
        if len(tasks) > 50:
            print(f"... {len(tasks) - 50} more")
        return 0

    manifest_path = args.manifest or args.output_dir / "download_manifest.jsonl"
    session = configure_session(args)
    results: list[ManifestRow] = []
    for index, task in enumerate(tasks, start=1):
        print(f"[{index}/{len(tasks)}] {task.course_code} {task.language} {task.course_name}")
        row = download_task(
            session,
            task,
            args.output_dir,
            timeout=args.timeout,
            retries=args.retries,
            force=args.force,
            method=args.method,
        )
        results.append(row)
        write_manifest_row(manifest_path, row)
        print(f"  -> {row.status} {row.detected_extension or ''} {row.output_path or row.error or ''}")
        if row.status == "login_or_empty_html" and not args.continue_on_login_html:
            print("Stopping because TIS returned HTML. Refresh the cookie/session and resume with --start-row/--start-task.")
            break
        if index < len(tasks):
            time.sleep(random.uniform(args.delay_min, args.delay_max))

    print_summary(results, len(tasks), skipped_without_url)
    print(f"Manifest: {manifest_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
