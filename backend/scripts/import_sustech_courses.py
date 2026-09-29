#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter, OrderedDict, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session

BACKEND_ROOT = Path(__file__).resolve().parents[1]
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from app.core.database import SessionLocal
from app.models import Course, CourseClass, CourseRate, CourseTerm, Dept, Teacher


UNKNOWN_TEACHER = "未知教师"


@dataclass
class ImportStats:
    files: int = 0
    records: int = 0
    groups: int = 0
    new_depts: int = 0
    updated_depts: int = 0
    new_teachers: int = 0
    new_courses: int = 0
    new_rates: int = 0
    new_terms: int = 0
    updated_terms: int = 0
    new_classes: int = 0
    updated_classes: int = 0
    remapped_class_aliases: set[str] = field(default_factory=set)
    preserved_ambiguous_class_aliases: set[str] = field(default_factory=set)
    filled_access_count: int = 0
    refreshed_course_codes: int = 0
    ambiguous_teacher_names: set[str] = field(default_factory=set)
    ambiguous_class_codes: Counter[str] = field(default_factory=Counter)
    mixed_group_fields: Counter[str] = field(default_factory=Counter)


@dataclass
class Group:
    term: str
    course_name: str
    teacher_names: tuple[str, ...]
    rows: list[dict[str, Any]] = field(default_factory=list)
    first_index: int = 0

    @property
    def key(self) -> str:
        return course_key(self.course_name, self.teacher_names)


def clean_text(value: Any, *, max_len: int | None = None) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    if not text or text.lower() in {"none", "null"}:
        return None
    if max_len is not None:
        return text[:max_len]
    return text


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


def normalize_course_code(value: Any) -> str | None:
    text = clean_text(value)
    if text is None:
        return None
    return text.replace(".", "").upper()


def normalize_level(value: Any) -> str | None:
    text = clean_text(value, max_len=20)
    if text in {"本科", "本"}:
        return "本科"
    if text in {"研究生", "硕士", "博士", "硕", "博"}:
        return "研究生"
    return text


def infer_course_level(row: dict[str, Any]) -> str | None:
    explicit = normalize_level(row.get("pyccmc"))
    if explicit:
        return explicit

    code = normalize_course_code(row.get("kcdm")) or ""
    candidates = [code]
    without_revision = re.sub(r"-[0-9]{2}[A-Z]?$", "", code)
    candidates.append(without_revision)
    candidates.append(re.sub(r"(?<=\d)[A-Z]$", "", without_revision))
    candidates.append(re.sub(r"(?<=\d)[A-Z]$", "", code))

    for candidate in OrderedDict.fromkeys(candidates):
        tail = candidate[-4:]
        if re.fullmatch(r"[0-9]{4}", tail):
            return "研究生"
        if re.fullmatch(r"[A-Z][0-9]{3}", tail):
            return "本科"
    return None


def parse_teacher_names(value: Any) -> tuple[str, ...]:
    text = clean_text(value)
    if text is None:
        return (UNKNOWN_TEACHER,)
    names = [
        item.strip()
        for item in re.split(r"[,，]", text)
        if item.strip() and item.strip().lower() not in {"none", "null"}
    ]
    if not names:
        return (UNKNOWN_TEACHER,)
    return tuple(sorted(OrderedDict.fromkeys(names)))


def course_key(name: str, teacher_names: tuple[str, ...] | list[str]) -> str:
    return f"{name}({','.join(sorted(set(teacher_names)))})"


def load_json_rows(path: Path) -> list[dict[str, Any]]:
    with path.open(encoding="utf-8") as handle:
        payload = json.load(handle)
    rows = payload.get("data", payload) if isinstance(payload, dict) else payload
    if not isinstance(rows, list):
        raise ValueError(f"{path} does not contain a course list")
    return rows


def infer_term(path: Path, rows: list[dict[str, Any]], override: str | None) -> str:
    if override:
        term = override.strip()
    else:
        term = ""
        filename_match = re.search(r"(20\d{2})-([123])", path.stem)
        if filename_match:
            term = f"{filename_match.group(1)}{filename_match.group(2)}"
        if not term:
            for row in rows:
                rwh = clean_text(row.get("rwh"))
                if not rwh:
                    continue
                rwh_match = re.match(r"(20\d{2})-\d{4}-([123])-", rwh)
                if rwh_match:
                    term = f"{rwh_match.group(1)}{rwh_match.group(2)}"
                    break
    if len(term) != 5 or not term[:4].isdigit() or term[4] not in "123":
        raise ValueError(f"Cannot infer a valid term for {path}; pass --term like 20251")
    return term


def first_non_empty(rows: list[dict[str, Any]], *keys: str, max_len: int | None = None) -> str | None:
    for row in rows:
        for key in keys:
            value = clean_text(row.get(key), max_len=max_len)
            if value is not None:
                return value
    return None


def first_number(rows: list[dict[str, Any]], key: str, *, integer: bool = False) -> int | float | None:
    parser = parse_int if integer else parse_float
    for row in rows:
        value = parser(row.get(key))
        if value is not None:
            return value
    return None


def unique_values(rows: list[dict[str, Any]], key: str) -> list[str]:
    values: OrderedDict[str, None] = OrderedDict()
    for row in rows:
        value = clean_text(row.get(key))
        if value is not None:
            values[value] = None
    return list(values)


def extract_week_range(rows: list[dict[str, Any]]) -> tuple[int | None, int | None]:
    for row in rows:
        raw = " ".join(
            item
            for item in [
                clean_text(row.get("pkjgmx")),
                clean_text(row.get("kcxx")),
            ]
            if item
        )
        text = re.sub(r"<[^>]+>", " ", raw)
        match = re.search(r"(\d{1,2})\s*-\s*(\d{1,2})\s*周", text)
        if match:
            return int(match.group(1)), int(match.group(2))
    return None, None


def dept_id_from_code(code: str) -> int | None:
    if code.isdigit():
        return int(code)
    return None


def assign_if_changed(obj: Any, attr: str, value: Any) -> bool:
    if getattr(obj, attr) != value:
        setattr(obj, attr, value)
        return True
    return False


def build_groups(path: Path, rows: list[dict[str, Any]], term: str) -> list[Group]:
    groups: OrderedDict[tuple[str, str], Group] = OrderedDict()
    for index, row in enumerate(rows):
        name = clean_text(row.get("kcmc"), max_len=80)
        if not name:
            print(f"Skipping row without kcmc in {path}: index={index}")
            continue
        teachers = parse_teacher_names(row.get("dgjsmc"))
        key = (term, course_key(name, teachers))
        if key not in groups:
            groups[key] = Group(term=term, course_name=name, teacher_names=teachers, first_index=index)
        groups[key].rows.append(row)
    return list(groups.values())


def load_existing(db: Session):
    depts_by_code = {dept.code: dept for dept in db.query(Dept).all() if dept.code}

    teachers_by_name: dict[str, list[Teacher]] = defaultdict(list)
    for teacher in db.query(Teacher).order_by(Teacher.id.asc()).all():
        if teacher.name:
            teachers_by_name[teacher.name].append(teacher)

    courses_by_key = {}
    for course in db.query(Course).all():
        if course.name:
            courses_by_key[course_key(course.name, course.teacher_name_list)] = course

    terms_by_course_term: dict[tuple[int, str], CourseTerm] = {}
    duplicate_terms = 0
    for term in db.query(CourseTerm).order_by(CourseTerm.id.asc()).all():
        if term.course_id is None or term.term is None:
            continue
        key = (term.course_id, str(term.term))
        if key in terms_by_course_term:
            duplicate_terms += 1
            continue
        terms_by_course_term[key] = term

    classes_by_term_cno = {
        (course_class.term, course_class.cno): course_class
        for course_class in db.query(CourseClass).all()
        if course_class.term and course_class.cno
    }

    return depts_by_code, teachers_by_name, courses_by_key, terms_by_course_term, classes_by_term_cno, duplicate_terms


def get_or_create_dept(
    db: Session,
    row: dict[str, Any],
    depts_by_code: dict[str, Dept],
    stats: ImportStats,
) -> Dept | None:
    code = clean_text(row.get("kkyx"), max_len=10)
    if not code:
        return None
    dept = depts_by_code.get(code)
    created = False
    if dept is None:
        dept = Dept(code=code)
        legacy_id = dept_id_from_code(code)
        if legacy_id is not None and db.get(Dept, legacy_id) is None:
            dept.id = legacy_id
        db.add(dept)
        depts_by_code[code] = dept
        stats.new_depts += 1
        created = True

    changed = False
    name = clean_text(row.get("kkyxmc"), max_len=100)
    name_eng = clean_text(row.get("kkyxmc_en"), max_len=200)
    if name is not None:
        changed |= assign_if_changed(dept, "name", name)
    if name_eng is not None:
        changed |= assign_if_changed(dept, "name_eng", name_eng)
    changed |= assign_if_changed(dept, "code", code)
    if changed and not created:
        stats.updated_depts += 1
    return dept


def get_or_create_teacher(
    db: Session,
    name: str,
    teachers_by_name: dict[str, list[Teacher]],
    stats: ImportStats,
) -> Teacher:
    existing = teachers_by_name.get(name, [])
    if existing:
        if len(existing) > 1:
            stats.ambiguous_teacher_names.add(name)
        return existing[0]
    teacher = Teacher(name=name, gender="unknown", access_count=0)
    db.add(teacher)
    teachers_by_name[name].append(teacher)
    stats.new_teachers += 1
    return teacher


def collect_term_payload(group: Group, stats: ImportStats) -> dict[str, Any]:
    rows = group.rows
    codes = [normalize_course_code(row.get("kcdm")) for row in rows]
    codes = [code for code in OrderedDict.fromkeys(codes) if code]
    representative = rows[-1]

    for field_name, json_key in [
        ("course_code", "kcdm"),
        ("department", "kkyx"),
        ("course_type", "kclbmc"),
        ("course_level", "pyccmc"),
    ]:
        values = unique_values(rows, json_key)
        if len(values) > 1:
            stats.mixed_group_fields[field_name] += 1

    hours = first_number(rows, "zxs", integer=True)
    hours_per_week = int(hours / 16) if isinstance(hours, int) and hours > 0 else None
    start_week, end_week = extract_week_range(rows)

    course_level = None
    for row in rows:
        course_level = infer_course_level(row)
        if course_level:
            break

    description = first_non_empty(rows, "course_desc_zh", max_len=None)
    description_eng = first_non_empty(rows, "course_desc_en", max_len=None)

    return {
        "term": group.term,
        "courseries": clean_text(codes[-1] if codes else normalize_course_code(representative.get("kcdm")), max_len=20),
        "class_numbers": clean_text(",".join(codes), max_len=200),
        "kcid": first_non_empty(rows, "kcid", "id", max_len=256),
        "course_major": first_non_empty(rows, "kkyxmc", max_len=20),
        "course_type": first_non_empty(rows, "kclbmc", max_len=20),
        "course_level": clean_text(course_level, max_len=20),
        "join_type": first_non_empty(rows, "rwlxmc", max_len=20),
        "teaching_type": first_non_empty(rows, "skyymc", max_len=20),
        "grading_type": first_non_empty(rows, "jfzlbmc", "khfs", "ksfs", max_len=20),
        "description": description,
        "description_eng": description_eng,
        "credit": first_number(rows, "xf"),
        "hours": hours,
        "hours_per_week": hours_per_week,
        "campus": first_non_empty(rows, "xiaoqumc", max_len=20),
        "start_week": start_week,
        "end_week": end_week,
        "codes": codes,
        "representative": representative,
    }


def upsert_group(
    db: Session,
    group: Group,
    caches,
    stats: ImportStats,
    *,
    remap_ambiguous_classes: bool,
) -> Course:
    depts_by_code, teachers_by_name, courses_by_key, terms_by_course_term, classes_by_term_cno = caches
    payload = collect_term_payload(group, stats)
    dept = get_or_create_dept(db, payload["representative"], depts_by_code, stats)

    teacher_objects = [
        get_or_create_teacher(db, name, teachers_by_name, stats)
        for name in group.teacher_names
    ]

    course = courses_by_key.get(group.key)
    if course is None:
        course = Course(name=group.course_name, access_count=0)
        course.teachers = teacher_objects
        db.add(course)
        db.flush()
        db.add(CourseRate(course=course))
        courses_by_key[group.key] = course
        stats.new_courses += 1
        stats.new_rates += 1
    else:
        if course.access_count is None:
            course.access_count = 0
            stats.filled_access_count += 1
        if course._course_rate is None:
            db.add(CourseRate(course=course))
            stats.new_rates += 1

    if dept is not None:
        course.dept_id = dept.id

    db.flush()
    term_key = (course.id, group.term)
    course_term = terms_by_course_term.get(term_key)
    term_is_new = course_term is None
    if term_is_new:
        course_term = CourseTerm(course=course, term=group.term)
        db.add(course_term)
        terms_by_course_term[term_key] = course_term
        stats.new_terms += 1

    changed = False
    for attr in [
        "term",
        "courseries",
        "kcid",
        "course_major",
        "course_type",
        "course_level",
        "join_type",
        "teaching_type",
        "grading_type",
        "description",
        "description_eng",
        "credit",
        "hours",
        "hours_per_week",
        "class_numbers",
        "campus",
        "start_week",
        "end_week",
    ]:
        changed |= assign_if_changed(course_term, attr, payload[attr])
    if changed and not term_is_new:
        stats.updated_terms += 1

    for code in payload["codes"]:
        class_key = (group.term, code)
        class_alias = f"{code}@{group.term}"
        course_class = classes_by_term_cno.get(class_key)
        class_is_new = course_class is None
        if class_is_new:
            course_class = CourseClass(term=group.term, cno=code)
            db.add(course_class)
            classes_by_term_cno[class_key] = course_class
            stats.new_classes += 1
        if course_class.course_id != course.id:
            if (
                not class_is_new
                and class_alias in stats.ambiguous_class_codes
                and not remap_ambiguous_classes
            ):
                stats.preserved_ambiguous_class_aliases.add(class_alias)
                continue
            course_class.course = course
            if not class_is_new:
                stats.remapped_class_aliases.add(class_alias)
                stats.updated_classes = len(stats.remapped_class_aliases)

    return course


def refresh_course_codes(db: Session, courses: set[Course], stats: ImportStats) -> None:
    for course in courses:
        latest_term = (
            db.query(CourseTerm)
            .filter(CourseTerm.course_id == course.id, CourseTerm.courseries.isnot(None))
            .order_by(CourseTerm.term.desc(), CourseTerm.id.desc())
            .first()
        )
        if latest_term and latest_term.courseries and course.course_code != latest_term.courseries:
            course.course_code = latest_term.courseries
            stats.refreshed_course_codes += 1


def flush_and_refresh_course_codes(db: Session, courses: set[Course], stats: ImportStats) -> None:
    """把本轮 CourseTerm 落库后，再按数据库中的最新学期刷新课程代码。"""
    # refresh_course_codes 通过 SQL 查询最新 CourseTerm；先 flush，确保即使调用方
    # 显式使用 autoflush=False，也能看到本轮刚新增/更新的学期记录。
    db.flush()
    refresh_course_codes(db, courses, stats)


def summarize_ambiguous_classes(groups: list[Group], stats: ImportStats) -> None:
    code_to_course_keys: dict[tuple[str, str], set[str]] = defaultdict(set)
    for group in groups:
        codes = {
            code
            for code in (normalize_course_code(row.get("kcdm")) for row in group.rows)
            if code
        }
        for code in codes:
            code_to_course_keys[(group.term, code)].add(group.key)
    for (term, code), keys in code_to_course_keys.items():
        if len(keys) > 1:
            stats.ambiguous_class_codes[f"{code}@{term}"] = len(keys)


def import_files(
    db: Session,
    paths: list[Path],
    term_override: str | None,
    *,
    remap_ambiguous_classes: bool,
) -> ImportStats:
    stats = ImportStats(files=len(paths))
    depts_by_code, teachers_by_name, courses_by_key, terms_by_course_term, classes_by_term_cno, duplicate_terms = load_existing(db)
    if duplicate_terms:
        print(f"Warning: ignored {duplicate_terms} duplicate existing course_terms rows while building cache")

    touched_courses: set[Course] = set()
    for path in paths:
        rows = load_json_rows(path)
        term = infer_term(path, rows, term_override)
        groups = build_groups(path, rows, term)
        summarize_ambiguous_classes(groups, stats)
        print(f"{path}: term={term}, records={len(rows)}, grouped_courses={len(groups)}")
        stats.records += len(rows)
        stats.groups += len(groups)

        # CourseClass is only a coarse code alias; ambiguous aliases are preserved by default.
        for group in groups:
            course = upsert_group(
                db,
                group,
                (depts_by_code, teachers_by_name, courses_by_key, terms_by_course_term, classes_by_term_cno),
                stats,
                remap_ambiguous_classes=remap_ambiguous_classes,
            )
            touched_courses.add(course)

    flush_and_refresh_course_codes(db, touched_courses, stats)
    db.flush()
    return stats


def print_stats(stats: ImportStats, *, committed: bool) -> None:
    print("\nImport summary")
    print(f"  files: {stats.files}")
    print(f"  source records: {stats.records}")
    print(f"  grouped courses: {stats.groups}")
    print(f"  departments: +{stats.new_depts}, updated={stats.updated_depts}")
    print(f"  teachers: +{stats.new_teachers}")
    print(f"  courses: +{stats.new_courses}, filled_access_count={stats.filled_access_count}")
    print(f"  course_rates: +{stats.new_rates}")
    print(f"  course_terms: +{stats.new_terms}, updated={stats.updated_terms}")
    print(f"  course_classes: +{stats.new_classes}, remapped={stats.updated_classes}")
    if stats.preserved_ambiguous_class_aliases:
        print(f"  preserved ambiguous CourseClass aliases: {len(stats.preserved_ambiguous_class_aliases)}")
    print(f"  refreshed courses.course_code: {stats.refreshed_course_codes}")
    if stats.ambiguous_teacher_names:
        names = ", ".join(sorted(stats.ambiguous_teacher_names)[:20])
        suffix = "..." if len(stats.ambiguous_teacher_names) > 20 else ""
        print(f"  ambiguous teacher names reused by lowest id: {names}{suffix}")
    if stats.ambiguous_class_codes:
        samples = ", ".join(
            f"{code}({count})"
            for code, count in stats.ambiguous_class_codes.most_common(20)
        )
        suffix = "..." if len(stats.ambiguous_class_codes) > 20 else ""
        print(f"  ambiguous CourseClass aliases: {samples}{suffix}")
    if stats.mixed_group_fields:
        samples = ", ".join(
            f"{field_name}={count}"
            for field_name, count in stats.mixed_group_fields.most_common()
        )
        print(f"  grouped rows with mixed metadata: {samples}")
    if committed:
        print("Committed changes.")
    else:
        print("Dry run complete; rolled back changes. Re-run with --commit to write.")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Import SUSTech course JSON into the NCES Next shared legacy database."
    )
    parser.add_argument("json_files", nargs="+", type=Path, help="SUSTech course JSON file(s), e.g. 2025-1.json")
    parser.add_argument("--term", help="Override term for all input files, e.g. 20251")
    parser.add_argument("--commit", action="store_true", help="Write changes. Default is dry-run with rollback.")
    parser.add_argument(
        "--remap-ambiguous-classes",
        action="store_true",
        help="Move ambiguous base course-code aliases between teacher-specific courses. Default preserves them.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    missing = [str(path) for path in args.json_files if not path.exists()]
    if missing:
        print("Missing input file(s): " + ", ".join(missing), file=sys.stderr)
        return 2

    db = SessionLocal()
    try:
        stats = import_files(
            db,
            args.json_files,
            args.term,
            remap_ambiguous_classes=args.remap_ambiguous_classes,
        )
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
