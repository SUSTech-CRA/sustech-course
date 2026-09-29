#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any


DEFAULT_INPUT_DIR = Path("/var/www/sustc-course-data/catalog")
DEFAULT_OUTPUT = Path("/var/www/sustc-course-data/course-catalog-202607-merged.json")


@dataclass
class PageInfo:
    path: str
    rows: int
    page_num: int | None = None
    page_size: int | None = None
    declared_total: int | None = None
    declared_pages: int | None = None


@dataclass
class MergeStats:
    files: int = 0
    input_rows: int = 0
    output_rows: int = 0
    duplicate_rows: int = 0
    replaced_duplicates: int = 0
    missing_key_rows: int = 0
    declared_totals: Counter[int] = field(default_factory=Counter)
    declared_pages: Counter[int] = field(default_factory=Counter)
    page_numbers: Counter[int] = field(default_factory=Counter)


def natural_key(path: Path) -> list[int | str]:
    parts = re.split(r"(\d+)", path.name)
    return [int(part) if part.isdigit() else part for part in parts]


def clean_text(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    if not text or text.lower() in {"none", "null"}:
        return None
    return text


def normalize_code(value: Any) -> str | None:
    text = clean_text(value)
    if text is None:
        return None
    return text.replace(".", "").upper()


def row_key(row: dict[str, Any], strategy: str) -> str | None:
    if strategy == "kcid":
        return clean_text(row.get("kcid"))
    if strategy == "kcdm":
        return normalize_code(row.get("kcdm"))
    if strategy == "kcdm-kcmc":
        code = normalize_code(row.get("kcdm"))
        name = clean_text(row.get("kcmc"))
        if code and name:
            return f"{code}:{name}"
        return code or name
    raise ValueError(f"Unsupported dedupe strategy: {strategy}")


def parse_time(value: Any) -> datetime | None:
    text = clean_text(value)
    if text is None:
        return None
    text = text.strip()
    for fmt, length in (("%Y-%m-%d %H:%M:%S", 19), ("%Y-%m-%d %H:%M", 16), ("%Y-%m-%d", 10)):
        try:
            return datetime.strptime(text[:length], fmt)
        except ValueError:
            pass
    return None


def row_timestamp(row: dict[str, Any]) -> datetime | None:
    return parse_time(row.get("zhxgsj")) or parse_time(row.get("cjsj")) or parse_time(row.get("sqsj"))


def should_replace(existing: dict[str, Any], incoming: dict[str, Any], policy: str) -> bool:
    if policy == "first":
        return False
    if policy == "last":
        return True
    if policy == "newest":
        existing_time = row_timestamp(existing)
        incoming_time = row_timestamp(incoming)
        if incoming_time is None:
            return False
        if existing_time is None:
            return True
        return incoming_time > existing_time
    raise ValueError(f"Unsupported duplicate policy: {policy}")


def load_rows(path: Path) -> tuple[list[dict[str, Any]], PageInfo]:
    with path.open(encoding="utf-8") as handle:
        payload = json.load(handle)

    if isinstance(payload, dict):
        rows = None
        for key in ("list", "data", "rows"):
            candidate = payload.get(key)
            if isinstance(candidate, list):
                rows = candidate
                break
        if rows is None:
            raise ValueError(f"{path} does not contain a top-level list/data/rows array")
        if not all(isinstance(row, dict) for row in rows):
            raise ValueError(f"{path} contains non-object rows")
        info = PageInfo(
            path=str(path),
            rows=len(rows),
            page_num=payload.get("pageNum") if isinstance(payload.get("pageNum"), int) else None,
            page_size=payload.get("pageSize") if isinstance(payload.get("pageSize"), int) else None,
            declared_total=payload.get("total") if isinstance(payload.get("total"), int) else None,
            declared_pages=payload.get("pages") if isinstance(payload.get("pages"), int) else None,
        )
        return rows, info

    if isinstance(payload, list):
        if not all(isinstance(row, dict) for row in payload):
            raise ValueError(f"{path} contains non-object rows")
        return payload, PageInfo(path=str(path), rows=len(payload))

    raise ValueError(f"{path} has unsupported JSON shape")


def discover_files(input_dir: Path, pattern: str) -> list[Path]:
    files = sorted(input_dir.glob(pattern), key=natural_key)
    return [path for path in files if path.is_file()]


def merge_pages(files: list[Path], *, dedupe_by: str, duplicate_policy: str) -> tuple[list[dict[str, Any]], list[PageInfo], MergeStats]:
    rows_by_key: dict[str, dict[str, Any]] = {}
    key_order: list[str] = []
    pages: list[PageInfo] = []
    stats = MergeStats(files=len(files))

    for path in files:
        rows, page = load_rows(path)
        pages.append(page)
        stats.input_rows += len(rows)
        if page.declared_total is not None:
            stats.declared_totals[page.declared_total] += 1
        if page.declared_pages is not None:
            stats.declared_pages[page.declared_pages] += 1
        if page.page_num is not None:
            stats.page_numbers[page.page_num] += 1

        for row in rows:
            key = row_key(row, dedupe_by)
            if key is None:
                stats.missing_key_rows += 1
                key = f"__missing_key__:{path.name}:{stats.input_rows}:{stats.missing_key_rows}"
            if key not in rows_by_key:
                rows_by_key[key] = row
                key_order.append(key)
                continue
            stats.duplicate_rows += 1
            if should_replace(rows_by_key[key], row, duplicate_policy):
                rows_by_key[key] = row
                stats.replaced_duplicates += 1

    merged = [rows_by_key[key] for key in key_order]
    stats.output_rows = len(merged)
    return merged, pages, stats


def build_payload(rows: list[dict[str, Any]], pages: list[PageInfo], stats: MergeStats) -> dict[str, Any]:
    page_size = len(rows)
    declared_total = stats.declared_totals.most_common(1)[0][0] if stats.declared_totals else len(rows)
    declared_pages = stats.declared_pages.most_common(1)[0][0] if stats.declared_pages else 1
    return {
        "total": len(rows),
        "declaredTotal": declared_total,
        "list": rows,
        "pageNum": 1,
        "pageSize": page_size,
        "size": len(rows),
        "startRow": 1 if rows else 0,
        "endRow": len(rows),
        "pages": 1,
        "source": {
            "files": [page.path for page in pages],
            "fileCount": stats.files,
            "inputRows": stats.input_rows,
            "outputRows": stats.output_rows,
            "duplicateRows": stats.duplicate_rows,
            "replacedDuplicates": stats.replaced_duplicates,
            "missingKeyRows": stats.missing_key_rows,
            "declaredPages": declared_pages,
            "pageNumbers": dict(sorted(stats.page_numbers.items())),
        },
    }


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, ensure_ascii=False, indent=2)
        handle.write("\n")


def print_summary(output: Path, stats: MergeStats) -> None:
    print(f"files: {stats.files}")
    print(f"input rows: {stats.input_rows}")
    print(f"output rows: {stats.output_rows}")
    print(f"duplicates removed: {stats.duplicate_rows}")
    print(f"duplicates replaced by newer row: {stats.replaced_duplicates}")
    if stats.missing_key_rows:
        print(f"rows without dedupe key kept: {stats.missing_key_rows}")
    if stats.declared_totals:
        totals = ", ".join(f"{total} ({count} files)" for total, count in sorted(stats.declared_totals.items()))
        print(f"declared totals: {totals}")
    if stats.page_numbers:
        repeated = {page: count for page, count in stats.page_numbers.items() if count > 1}
        if repeated:
            print(f"repeated page numbers: {repeated}")
    print(f"wrote: {output}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Merge paginated SUSTech course-catalog JSON files into one deduplicated catalog."
    )
    parser.add_argument(
        "input_dir",
        nargs="?",
        type=Path,
        default=DEFAULT_INPUT_DIR,
        help=f"Directory containing page JSON files (default: {DEFAULT_INPUT_DIR})",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT,
        help=f"Merged JSON output path (default: {DEFAULT_OUTPUT})",
    )
    parser.add_argument(
        "--pattern",
        default="*.json",
        help="Glob pattern used inside input_dir (default: *.json)",
    )
    parser.add_argument(
        "--dedupe-by",
        choices=("kcid", "kcdm", "kcdm-kcmc"),
        default="kcid",
        help="Row key used for deduplication (default: kcid)",
    )
    parser.add_argument(
        "--duplicate-policy",
        choices=("first", "last", "newest"),
        default="newest",
        help="Which duplicate row to keep (default: newest by zhxgsj/cjsj/sqsj)",
    )
    parser.add_argument(
        "--list-only",
        action="store_true",
        help="Write a raw JSON array instead of a PageInfo-like object with top-level list",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    files = discover_files(args.input_dir, args.pattern)
    if not files:
        raise SystemExit(f"No JSON files matched {args.input_dir / args.pattern}")

    rows, pages, stats = merge_pages(files, dedupe_by=args.dedupe_by, duplicate_policy=args.duplicate_policy)
    payload: Any = rows if args.list_only else build_payload(rows, pages, stats)
    write_json(args.output, payload)
    print_summary(args.output, stats)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
