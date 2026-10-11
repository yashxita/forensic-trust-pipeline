"""Module 1: dual-parser comparator.

Parses the same database with two independent parsers and flags any difference.
A single compromised parser cannot silently change the result, because the
second parser (different code base, different language runtime path) will
disagree and the case is escalated to manual review.

Usage:
    python -m comparator.compare --demo
    python -m comparator.compare path/to/file.db [--table messages]
"""
import argparse
import sys
from pathlib import Path

import ui
from comparator import parser_a, parser_b
from data.make_sample_db import DB_PATH, build


def _sorted_keys(keys):
    try:
        return sorted(keys)
    except TypeError:
        return sorted(keys, key=repr)


def compare(result_a, result_b):
    cols_a, rows_a = result_a
    cols_b, rows_b = result_b
    map_a = {r[0]: r for r in rows_a}
    map_b = {r[0]: r for r in rows_b}
    report = {
        "columns_match": list(cols_a) == list(cols_b),
        "count_a": len(rows_a),
        "count_b": len(rows_b),
        "only_in_a": [],
        "only_in_b": [],
        "field_diffs": [],
    }
    for key in _sorted_keys(set(map_a) | set(map_b)):
        ra, rb = map_a.get(key), map_b.get(key)
        if rb is None:
            report["only_in_a"].append(key)
        elif ra is None:
            report["only_in_b"].append(key)
        elif ra != rb:
            for i, (x, y) in enumerate(zip(ra, rb)):
                if x != y:
                    report["field_diffs"].append((key, cols_a[i], x, y))
    report["agree"] = (
        report["columns_match"]
        and not report["only_in_a"]
        and not report["only_in_b"]
        and not report["field_diffs"]
        and report["count_a"] == report["count_b"]
    )
    return report


def print_report(report, label_a="Parser A", label_b="Parser B", limit=10):
    ui.table(
        ["Check", label_a, label_b],
        [
            ["Rows parsed", report["count_a"], report["count_b"]],
            ["Column names match", "-", "yes" if report["columns_match"] else "NO"],
            ["Rows only in this parser", len(report["only_in_a"]), len(report["only_in_b"])],
            ["Field-level differences", len(report["field_diffs"]), ""],
        ],
    )
    for key in report["only_in_a"][:limit]:
        print(f"  - id {key}: present in {label_a} only")
    for key in report["only_in_b"][:limit]:
        print(f"  - id {key}: present in {label_b} only")
    for key, col, x, y in report["field_diffs"][:limit]:
        print(f"  - id {key}, column '{col}': {label_a}={x!r} vs {label_b}={y!r}")
    if report["agree"]:
        ui.ok("VERDICT: AGREE. Both parsers produced identical output.")
    else:
        ui.fail("VERDICT: DIVERGENCE. Escalate to manual analysis before trusting this report.")


def simulate_compromised_output(cols, rows):
    """What a compromised parser could return: hide, alter and inject records."""
    rows = [list(r) for r in rows]
    changes = []
    hidden = rows.pop(41)
    changes.append(f"hid message id={hidden[0]}")
    ts = cols.index("sent_at")
    target = rows[100]
    target[ts] = "2021-01-01T00:00:00"
    changes.append(f"altered timestamp of message id={target[0]}")
    new_id = max(r[0] for r in rows) + 1
    rows.append([new_id, "+91-90000-00000", "+91-90000-01111", "injected record", "2026-03-05T10:00:00", "out"])
    changes.append(f"injected fake message id={new_id}")
    return cols, [tuple(r) for r in rows], changes


def run_demo():
    ui.banner("MODULE 1: DUAL-PARSER COMPARATOR (report Section 10.2)")
    db = build(DB_PATH)
    ui.info(f"Sample evidence database: {db.name} ({db.stat().st_size} bytes)")

    ui.section("Step 1: honest run, two independent parsers")
    ui.info("Parser A = Python sqlite3 (C library). Parser B = pure-Python file-format reader.")
    result_a = parser_a.parse(db)
    result_b = parser_b.parse(db)
    honest = compare(result_a, result_b)
    print_report(honest)

    ui.section("Step 2: Parser A is compromised and tampers with its own output")
    cols, bad_rows, changes = simulate_compromised_output(*result_a)
    for c in changes:
        ui.warn(f"attacker action: {c}")
    tampered = compare((cols, bad_rows), result_b)
    print_report(tampered, label_a="Parser A*", label_b="Parser B")

    ui.section("Result")
    passed = honest["agree"] and not tampered["agree"]
    if passed:
        ui.ok("Honest run agreed; tampering in one parser was detected by the other.")
    else:
        ui.fail("Demo did not behave as expected.")
    return 0 if passed else 1


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("db", nargs="?", help="SQLite file to compare with both parsers")
    ap.add_argument("--table", default="messages")
    ap.add_argument("--demo", action="store_true", help="run the tamper-detection demo")
    args = ap.parse_args()
    if args.demo or not args.db:
        return run_demo()
    path = Path(args.db)
    try:
        result_b = parser_b.parse(path, args.table)
    except parser_b.ParseError as exc:
        ui.fail(f"Parser B rejected the file: {exc}")
        return 2
    report = compare(parser_a.parse(path, args.table), result_b)
    print_report(report)
    return 0 if report["agree"] else 2


if __name__ == "__main__":
    sys.exit(main())
