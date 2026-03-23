"""Detect query anti-patterns: N+1, slow queries, duplicates."""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field

from .capture import CaptureSession, CapturedQuery


@dataclass
class QueryIssue:
    """A detected query anti-pattern."""

    type: str  # 'n_plus_one', 'slow', 'duplicate', 'missing_index'
    severity: str  # 'high', 'medium', 'low'
    description: str
    queries: list[int]  # Indices of involved queries
    suggestion: str


@dataclass
class DetectionReport:
    """Report of all detected query issues."""

    issues: list[QueryIssue] = field(default_factory=list)
    total_queries: int = 0
    total_duration_ms: float = 0.0
    unique_queries: int = 0

    def summary(self) -> str:
        lines = [
            "Query Analysis Report",
            "=" * 50,
            f"Total queries:  {self.total_queries}",
            f"Unique queries: {self.unique_queries}",
            f"Total time:     {self.total_duration_ms:.1f}ms",
            f"Issues found:   {len(self.issues)}",
            "",
        ]

        by_severity = {"high": [], "medium": [], "low": []}
        for issue in self.issues:
            by_severity[issue.severity].append(issue)

        for sev in ("high", "medium", "low"):
            if by_severity[sev]:
                lines.append(f"--- {sev.upper()} severity ---")
                for issue in by_severity[sev]:
                    lines.append(f"  [{issue.type}] {issue.description}")
                    lines.append(f"    Queries: {issue.queries[:5]}{'...' if len(issue.queries) > 5 else ''}")
                    lines.append(f"    Fix: {issue.suggestion}")
                    lines.append("")

        return "\n".join(lines)


def _normalize_sql(sql: str) -> str:
    """Normalize SQL for comparison: strip whitespace, lowercase, replace params."""
    sql = " ".join(sql.split()).lower().strip().rstrip(";")
    # Replace string literals
    sql = re.sub(r"'[^']*'", "'?'", sql)
    # Replace numbers
    sql = re.sub(r"\b\d+\b", "?", sql)
    return sql


def _extract_table(sql: str) -> str | None:
    """Extract the main table name from a SQL query."""
    sql_upper = sql.upper()
    # FROM clause
    match = re.search(r"\bFROM\s+([`\"\w]+)", sql_upper)
    if match:
        return match.group(1).strip('`"').lower()
    # INSERT INTO
    match = re.search(r"\bINTO\s+([`\"\w]+)", sql_upper)
    if match:
        return match.group(1).strip('`"').lower()
    return None


def detect_n_plus_one(session: CaptureSession, threshold: int = 3) -> list[QueryIssue]:
    """Detect N+1 query patterns.

    Looks for repeated similar SELECT queries that differ only in parameter values,
    executed in rapid succession.
    """
    issues = []
    normalized = [(_normalize_sql(q.sql), i) for i, q in enumerate(session.queries)]

    # Group consecutive similar queries
    groups: dict[str, list[int]] = {}
    for norm, idx in normalized:
        if norm.startswith("select"):
            if norm not in groups:
                groups[norm] = []
            groups[norm].append(idx)

    for norm, indices in groups.items():
        if len(indices) >= threshold:
            # Check if they're roughly consecutive (within a window)
            consecutive_runs = []
            current_run = [indices[0]]
            for i in range(1, len(indices)):
                if indices[i] - indices[i - 1] <= 5:  # Within 5 queries of each other
                    current_run.append(indices[i])
                else:
                    if len(current_run) >= threshold:
                        consecutive_runs.append(current_run)
                    current_run = [indices[i]]
            if len(current_run) >= threshold:
                consecutive_runs.append(current_run)

            for run in consecutive_runs:
                table = _extract_table(session.queries[run[0]].sql)
                issues.append(QueryIssue(
                    type="n_plus_one",
                    severity="high",
                    description=f"N+1 pattern: {len(run)} similar queries on '{table or 'unknown'}' table",
                    queries=run,
                    suggestion=f"Use a JOIN or IN clause to batch these {len(run)} queries into one",
                ))

    return issues


def detect_slow_queries(session: CaptureSession, threshold_ms: float = 100.0) -> list[QueryIssue]:
    """Detect queries slower than the threshold."""
    issues = []

    for i, q in enumerate(session.queries):
        if q.duration_ms >= threshold_ms:
            table = _extract_table(q.sql)
            issues.append(QueryIssue(
                type="slow",
                severity="high" if q.duration_ms > threshold_ms * 5 else "medium",
                description=f"Slow query ({q.duration_ms:.1f}ms) on '{table or 'unknown'}'",
                queries=[i],
                suggestion="Add an index, optimize the query, or check for missing WHERE clause",
            ))

    return issues


def detect_duplicates(session: CaptureSession, threshold: int = 2) -> list[QueryIssue]:
    """Detect exact duplicate queries (same SQL + same params)."""
    issues = []

    seen: dict[str, list[int]] = {}
    for i, q in enumerate(session.queries):
        key = f"{q.sql}|{q.params}"
        if key not in seen:
            seen[key] = []
        seen[key].append(i)

    for key, indices in seen.items():
        if len(indices) >= threshold:
            sql = session.queries[indices[0]].sql
            table = _extract_table(sql)
            total_ms = sum(session.queries[i].duration_ms for i in indices)
            issues.append(QueryIssue(
                type="duplicate",
                severity="medium",
                description=f"Duplicate query executed {len(indices)} times on '{table or 'unknown'}' ({total_ms:.1f}ms total)",
                queries=indices,
                suggestion="Cache the result or restructure to avoid repeated identical queries",
            ))

    return issues


def detect_missing_where(session: CaptureSession) -> list[QueryIssue]:
    """Detect SELECT/UPDATE/DELETE queries without WHERE clause."""
    issues = []

    for i, q in enumerate(session.queries):
        sql_upper = q.sql.strip().upper()
        if sql_upper.startswith(("UPDATE", "DELETE")):
            if "WHERE" not in sql_upper:
                issues.append(QueryIssue(
                    type="missing_where",
                    severity="high",
                    description=f"{'UPDATE' if 'UPDATE' in sql_upper else 'DELETE'} without WHERE clause",
                    queries=[i],
                    suggestion="Add a WHERE clause to avoid affecting all rows",
                ))
        elif sql_upper.startswith("SELECT") and "WHERE" not in sql_upper:
            table = _extract_table(q.sql)
            if q.rows_affected > 1000:
                issues.append(QueryIssue(
                    type="missing_where",
                    severity="low",
                    description=f"SELECT without WHERE on '{table or 'unknown'}' ({q.rows_affected} rows)",
                    queries=[i],
                    suggestion="Consider adding filters or pagination",
                ))

    return issues


def analyze(session: CaptureSession, slow_threshold_ms: float = 100.0) -> DetectionReport:
    """Run all detectors and produce a combined report.

    Args:
        session: The captured query session to analyze.
        slow_threshold_ms: Threshold for slow query detection.

    Returns:
        DetectionReport with all found issues.
    """
    normalized_set = set(_normalize_sql(q.sql) for q in session.queries)

    report = DetectionReport(
        total_queries=session.query_count,
        total_duration_ms=session.total_duration_ms,
        unique_queries=len(normalized_set),
    )

    report.issues.extend(detect_n_plus_one(session))
    report.issues.extend(detect_slow_queries(session, slow_threshold_ms))
    report.issues.extend(detect_duplicates(session))
    report.issues.extend(detect_missing_where(session))

    # Sort by severity
    severity_order = {"high": 0, "medium": 1, "low": 2}
    report.issues.sort(key=lambda x: severity_order.get(x.severity, 3))

    return report
