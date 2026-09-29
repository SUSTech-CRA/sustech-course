#!/usr/bin/env python3
from __future__ import annotations

import argparse
import html
import json
import re
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from lxml import html as lxml_html
from sqlalchemy.orm import Session

BACKEND_ROOT = Path(__file__).resolve().parents[1]
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from app.core.database import SessionLocal
from app.models import Course, CourseTerm, Dept


PLACEHOLDERS = {"无", "暂无", "请补充", "none", "null", "n/a", "na", "未填写"}


@dataclass
class CatalogStats:
    rows: int = 0
    declared_total: int | None = None
    matched_rows: int = 0
    updated_courses: set[int] = field(default_factory=set)
    updated_terms: set[int] = field(default_factory=set)
    no_match: int = 0
    ambiguous_name: int = 0
    no_term: int = 0
    tied_latest: int = 0
    source_counts: Counter[str] = field(default_factory=Counter)
    field_changes: Counter[str] = field(default_factory=Counter)
    skipped_examples: dict[str, list[str]] = field(default_factory=lambda: defaultdict(list))


@dataclass
class CourseIndex:
    by_kcid: dict[str, set[int]]
    by_code: dict[str, set[int]]
    by_name: dict[str, set[int]]
    latest_term_by_course: dict[int, CourseTerm]
    latest_term_value_by_course: dict[int, str]
    dept_by_name: dict[str, Dept]
    dept_by_name_eng: dict[str, Dept]


def clean_text(value: Any, *, max_len: int | None = None) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    if not text or text.lower() in {"none", "null"}:
        return None
    if max_len is not None:
        return text[:max_len]
    return text


def normalize_code(value: Any) -> str | None:
    text = clean_text(value)
    if text is None:
        return None
    return text.replace(".", "").upper()


def parse_float(value: Any) -> float | None:
    text = clean_text(value)
    if text is None:
        return None
    try:
        return float(text)
    except ValueError:
        return None


def parse_int(value: Any) -> int | None:
    number = parse_float(value)
    if number is None:
        return None
    return int(number)


def html_to_text(value: Any) -> str | None:
    text = clean_text(value)
    if text is None:
        return None
    try:
        if "<" in text and ">" in text:
            root = lxml_html.fromstring(f"<div>{text}</div>")
            text = root.text_content()
    except Exception:
        text = re.sub(r"<[^>]+>", " ", text)
    text = html.unescape(text)
    text = re.sub(r"\r\n?|\n", "\n", text)
    text = re.sub(r"[ \t\f\v]+", " ", text)
    text = re.sub(r" *\n *", "\n", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    text = text.strip()
    return None if not text or text.lower() in PLACEHOLDERS else text


def catalog_level(row: dict[str, Any]) -> str | None:
    level = clean_text(row.get("pylbmc"), max_len=20)
    if level:
        if level in {"本科", "研究生", "本科研究生"}:
            return level
        if "研" in level:
            return "研究生"
        if "本" in level:
            return "本科"

    gradation = clean_text(row.get("pyccdm"), max_len=20)
    if gradation:
        if "硕" in gradation or "博" in gradation or "研" in gradation:
            return "研究生"
        if "本科" in gradation:
            return "本科"

    legacy = clean_text(row.get("glqxmc"), max_len=20)
    if legacy == "研":
        return "研究生"
    if legacy == "本":
        return "本科"
    return infer_level_from_code(row.get("kcdm"))


def infer_level_from_code(value: Any) -> str | None:
    code = normalize_code(value) or ""
    candidates = [code]
    without_revision = re.sub(r"-[0-9]{2}[A-Z]?$", "", code)
    candidates.append(without_revision)
    candidates.append(re.sub(r"(?<=\d)[A-Z]$", "", without_revision))
    candidates.append(re.sub(r"(?<=\d)[A-Z]$", "", code))
    for candidate in dict.fromkeys(candidates):
        tail = candidate[-4:]
        if re.fullmatch(r"[0-9]{4}", tail):
            return "研究生"
        if re.fullmatch(r"[A-Z][0-9]{3}", tail):
            return "本科"
    return None


def first_text(row: dict[str, Any], *keys: str, max_len: int | None = None) -> str | None:
    for key in keys:
        value = clean_text(row.get(key), max_len=max_len)
        if value is not None and value.lower() not in PLACEHOLDERS:
            return value
    return None


def grading_type(row: dict[str, Any]) -> str | None:
    values = []
    for key in ("khfsdm", "jffs"):
        value = first_text(row, key, max_len=20)
        if value and value not in values:
            values.append(value)
    if not values:
        return None
    return "/".join(values)[:20]


def student_requirements(row: dict[str, Any]) -> str | None:
    zh = first_text(row, "xxkcms", max_len=400)
    en = first_text(row, "xxkcywms", max_len=400)
    parts = []
    if zh:
        parts.append(f"先修课程：{zh}")
    if en:
        parts.append(f"Prerequisites: {en}")
    return "\n".join(parts) if parts else None


def load_catalog_rows(path: Path) -> tuple[list[dict[str, Any]], int | None]:
    with path.open(encoding="utf-8") as handle:
        payload = json.load(handle)

    declared_total = payload.get("total") if isinstance(payload, dict) else None
    if isinstance(payload, dict):
        for key in ("list", "data", "rows"):
            rows = payload.get(key)
            if isinstance(rows, list):
                return rows, declared_total if isinstance(declared_total, int) else None
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


def build_index(db: Session) -> CourseIndex:
    by_kcid: dict[str, set[int]] = defaultdict(set)
    by_code: dict[str, set[int]] = defaultdict(set)
    by_name: dict[str, set[int]] = defaultdict(set)
    latest_term_by_course: dict[int, CourseTerm] = {}
    latest_term_value_by_course: dict[int, str] = {}

    for course in db.query(Course).all():
        if course.name:
            by_name[course.name.strip()].add(course.id)
        code = normalize_code(course.course_code)
        if code:
            by_code[code].add(course.id)

    for term in db.query(CourseTerm).order_by(CourseTerm.term.asc(), CourseTerm.id.asc()).all():
        if term.course_id is None:
            continue
        kcid = clean_text(term.kcid)
        if kcid:
            by_kcid[kcid].add(term.course_id)
        code = normalize_code(term.courseries)
        if code:
            by_code[code].add(term.course_id)
        term_value = clean_text(term.term) or ""
        current_value = latest_term_value_by_course.get(term.course_id, "")
        if term_value >= current_value:
            latest_term_value_by_course[term.course_id] = term_value
            latest_term_by_course[term.course_id] = term

    dept_by_name: dict[str, Dept] = {}
    dept_by_name_eng: dict[str, Dept] = {}
    duplicated_names: set[str] = set()
    duplicated_names_eng: set[str] = set()
    for dept in db.query(Dept).all():
        if dept.name:
            if dept.name in dept_by_name:
                duplicated_names.add(dept.name)
            dept_by_name[dept.name] = dept
        if dept.name_eng:
            if dept.name_eng in dept_by_name_eng:
                duplicated_names_eng.add(dept.name_eng)
            dept_by_name_eng[dept.name_eng] = dept
    for name in duplicated_names:
        dept_by_name.pop(name, None)
    for name in duplicated_names_eng:
        dept_by_name_eng.pop(name, None)

    return CourseIndex(
        by_kcid=by_kcid,
        by_code=by_code,
        by_name=by_name,
        latest_term_by_course=latest_term_by_course,
        latest_term_value_by_course=latest_term_value_by_course,
        dept_by_name=dept_by_name,
        dept_by_name_eng=dept_by_name_eng,
    )


def add_example(stats: CatalogStats, key: str, row: dict[str, Any], extra: str = "") -> None:
    examples = stats.skipped_examples[key]
    if len(examples) >= 8:
        return
    code = clean_text(row.get("kcdm")) or "?"
    name = clean_text(row.get("kcmc")) or "?"
    suffix = f" {extra}" if extra else ""
    examples.append(f"{code} {name}{suffix}")


def match_courses(row: dict[str, Any], index: CourseIndex, stats: CatalogStats) -> tuple[str | None, set[int]]:
    kcid = clean_text(row.get("kcid"))
    if kcid and index.by_kcid.get(kcid):
        return "kcid", set(index.by_kcid[kcid])

    code = normalize_code(row.get("kcdm"))
    if code and index.by_code.get(code):
        return "code", set(index.by_code[code])

    name = clean_text(row.get("kcmc"))
    if name and index.by_name.get(name):
        matches = set(index.by_name[name])
        if len(matches) == 1:
            return "name", matches
        stats.ambiguous_name += 1
        add_example(stats, "ambiguous_name", row, f"matches={len(matches)}")
        return None, set()

    stats.no_match += 1
    add_example(stats, "no_match", row)
    return None, set()


def latest_course_ids(candidate_ids: set[int], index: CourseIndex, stats: CatalogStats) -> set[int]:
    if not candidate_ids:
        return set()
    latest_value = max(index.latest_term_value_by_course.get(course_id, "") for course_id in candidate_ids)
    selected = {
        course_id
        for course_id in candidate_ids
        if index.latest_term_value_by_course.get(course_id, "") == latest_value
    }
    if len(selected) > 1:
        stats.tied_latest += 1
    return selected


def dept_from_catalog(row: dict[str, Any], index: CourseIndex) -> Dept | None:
    name = clean_text(row.get("yxmc"))
    if name and name in index.dept_by_name:
        return index.dept_by_name[name]
    name_eng = clean_text(row.get("yxmc_en"))
    if name_eng and name_eng in index.dept_by_name_eng:
        return index.dept_by_name_eng[name_eng]
    return None


def assign_if_changed(obj: Any, attr: str, value: Any, stats: CatalogStats, field_name: str) -> bool:
    if value is None:
        return False
    if getattr(obj, attr) != value:
        setattr(obj, attr, value)
        stats.field_changes[field_name] += 1
        return True
    return False


def update_course_and_term(db: Session, row: dict[str, Any], course_id: int, index: CourseIndex, stats: CatalogStats) -> None:
    course = db.get(Course, course_id)
    if course is None:
        return

    code = normalize_code(row.get("kcdm"))
    course_changed = assign_if_changed(course, "course_code", code, stats, "courses.course_code")

    dept = dept_from_catalog(row, index)
    if dept is not None and course.dept_id != dept.id:
        course.dept_id = dept.id
        stats.field_changes["courses.dept_id"] += 1
        course_changed = True

    term = index.latest_term_by_course.get(course_id)
    if term is None:
        if course_changed:
            stats.updated_courses.add(course.id)
        stats.no_term += 1
        add_example(stats, "no_term", row, f"course_id={course_id}")
        return

    payload = {
        "courseries": code,
        "kcid": clean_text(row.get("kcid"), max_len=256),
        "course_major": first_text(row, "yxmc", max_len=20),
        "course_type": first_text(row, "kclbmc", "kclbmc1", max_len=20),
        "course_level": catalog_level(row),
        "join_type": first_text(row, "rwlxmc", max_len=20),
        "teaching_type": first_text(row, "skyymc", max_len=20),
        "grading_type": grading_type(row),
        "description": html_to_text(row.get("kczwjj")),
        "description_eng": html_to_text(row.get("kcywjj")),
        "student_requirements": student_requirements(row),
        "credit": parse_float(row.get("xf")),
        "hours": parse_int(row.get("sjzxs")) or parse_int(row.get("xszxs")),
    }
    if payload["hours"] is not None:
        payload["hours_per_week"] = int(payload["hours"] / 16) if payload["hours"] > 0 else 0
    else:
        payload["hours_per_week"] = None

    term_changed = False
    for attr, value in payload.items():
        term_changed |= assign_if_changed(term, attr, value, stats, f"course_terms.{attr}")

    if course_changed:
        stats.updated_courses.add(course.id)
    if term_changed:
        stats.updated_terms.add(term.id)


def update_from_catalog(db: Session, rows: list[dict[str, Any]], declared_total: int | None) -> CatalogStats:
    stats = CatalogStats(rows=len(rows), declared_total=declared_total)
    index = build_index(db)

    for row in rows:
        source, candidates = match_courses(row, index, stats)
        if source is None:
            continue
        selected = latest_course_ids(candidates, index, stats)
        if not selected:
            stats.no_match += 1
            add_example(stats, "no_match", row, "no latest term")
            continue
        stats.matched_rows += 1
        stats.source_counts[source] += 1
        for course_id in selected:
            update_course_and_term(db, row, course_id, index, stats)

    db.flush()
    return stats


def print_stats(stats: CatalogStats, *, committed: bool) -> None:
    print("\nCatalog metadata update summary")
    print(f"  source rows: {stats.rows}")
    if stats.declared_total is not None and stats.declared_total > stats.rows:
        print(f"  warning: JSON declares total={stats.declared_total}, but contains {stats.rows} row(s)")
    print(f"  matched rows: {stats.matched_rows}")
    print(f"  match sources: {dict(stats.source_counts)}")
    print(f"  latest-match ties: {stats.tied_latest}")
    print(f"  updated courses: {len(stats.updated_courses)}")
    print(f"  updated course_terms: {len(stats.updated_terms)}")
    print(f"  skipped no-match rows: {stats.no_match}")
    print(f"  skipped ambiguous-name rows: {stats.ambiguous_name}")
    print(f"  matched courses without terms: {stats.no_term}")
    if stats.field_changes:
        print("  changed fields:")
        for field_name, count in stats.field_changes.most_common():
            print(f"    {field_name}: {count}")
    for key, examples in stats.skipped_examples.items():
        if examples:
            print(f"  {key} examples:")
            for example in examples:
                print(f"    - {example}")
    if committed:
        print("Committed changes.")
    else:
        print("Dry run complete; rolled back changes. Re-run with --commit to write.")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Update existing NCES course metadata from SUSTech course catalog JSON."
    )
    parser.add_argument("catalog_json", type=Path, help="Course catalog JSON file")
    parser.add_argument("--commit", action="store_true", help="Write changes. Default is dry-run with rollback.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if not args.catalog_json.exists():
        print(f"Missing input file: {args.catalog_json}", file=sys.stderr)
        return 2

    rows, declared_total = load_catalog_rows(args.catalog_json)
    db = SessionLocal()
    try:
        stats = update_from_catalog(db, rows, declared_total)
        if args.commit:
            db.commit()
        else:
            db.rollback()
        print_stats(stats, committed=args.commit)
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
