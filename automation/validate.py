"""Static validation for generated KQL detections.

This does NOT execute queries (no Defender tenant is connected). It checks:
  * balanced parentheses / brackets / quotes
  * the query starts from a known Advanced Hunting table
  * every table referenced is a known Advanced Hunting table (hard error)
  * columns in `project` reference known columns (warning only - schema is partial)

Table names are treated as errors; unknown columns are warnings, because the
bundled schema is intentionally a curated subset, not the full catalog.
"""
from __future__ import annotations

import json
import pathlib
import re

_SCHEMA_PATH = pathlib.Path(__file__).parent / "schema" / "defender_tables.json"
_SCHEMA = {k: v for k, v in json.loads(_SCHEMA_PATH.read_text()).items() if not k.startswith("_")}
_TABLES = set(_SCHEMA)


class ValidationResult:
    def __init__(self) -> None:
        self.errors: list[str] = []
        self.warnings: list[str] = []

    @property
    def ok(self) -> bool:
        return not self.errors

    def __str__(self) -> str:
        lines = []
        for e in self.errors:
            lines.append(f"  ERROR:   {e}")
        for w in self.warnings:
            lines.append(f"  WARNING: {w}")
        return "\n".join(lines) or "  (clean)"


def _balanced(query: str, res: ValidationResult) -> None:
    pairs = {")": "(", "]": "["}
    stack: list[str] = []
    in_str = None
    for ch in query:
        if in_str:
            if ch == in_str:
                in_str = None
            continue
        if ch in ("'", '"'):
            in_str = ch
        elif ch in "([":
            stack.append(ch)
        elif ch in ")]":
            if not stack or stack.pop() != pairs[ch]:
                res.errors.append(f"unbalanced '{ch}'")
                return
    if in_str:
        res.errors.append(f"unterminated string (opened with {in_str})")
    if stack:
        res.errors.append(f"unclosed '{stack[-1]}'")


def _tables_referenced(query: str) -> set[str]:
    # Advanced Hunting table names are PascalCase identifiers used as the query
    # source or after a join/union. Match capitalized identifiers and keep the
    # ones that look like table references.
    found = set()
    # first non-comment, non-empty token is the source table
    for line in query.splitlines():
        line = line.strip()
        if not line or line.startswith("//"):
            continue
        m = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)", line)
        if m:
            found.add(m.group(1))
        break
    # join/union references
    for m in re.finditer(r"\b(?:join(?:\s+kind\s*=\s*\w+)?|union)\s+\(?\s*([A-Z][A-Za-z0-9_]*)", query):
        found.add(m.group(1))
    return found


def validate(query: str, tactic: str | None = None) -> ValidationResult:
    res = ValidationResult()
    query = query.strip()
    if not query:
        res.errors.append("empty query")
        return res

    _balanced(query, res)

    # Source table must be a known Advanced Hunting table.
    first = _tables_referenced(query)
    if not first:
        res.errors.append("could not identify a source table")
    for t in first:
        if t not in _TABLES:
            res.errors.append(f"unknown table '{t}' (not a known Advanced Hunting table)")

    # Must pipe into at least one operator.
    if "|" not in query:
        res.warnings.append("query has no pipe operators - is it a real hunting query?")

    # Column checks in project (warnings only).
    for proj in re.finditer(r"\|\s*project(?:-\w+)?\s+([^|]+)", query):
        cols = re.findall(r"[A-Za-z_][A-Za-z0-9_]*", proj.group(1))
        known_cols = set()
        for t in first:
            known_cols |= set(_SCHEMA.get(t, []))
        for c in cols:
            # skip aliases like `X = Y` right-hand handled loosely
            if c not in known_cols and c[0].isupper() and c not in _TABLES:
                res.warnings.append(f"column '{c}' not in known schema for {sorted(first)}")

    return res


if __name__ == "__main__":  # smoke test against a couple of sample queries
    good = """DeviceProcessEvents
| where Timestamp > ago(1d)
| where FileName in~ ("powershell.exe","pwsh.exe")
| where ProcessCommandLine has_any ("-enc","FromBase64String")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
| order by Timestamp desc"""
    bad = """MadeUpTable
| where Foo == "bar"
| project Timestamp, Nonexistent (unterminated"""
    for label, q in (("GOOD", good), ("BAD", bad)):
        r = validate(q)
        print(f"[{label}] ok={r.ok}")
        print(r)
