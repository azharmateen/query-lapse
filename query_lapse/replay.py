"""Replay captured queries against a test database and compare results."""

from __future__ import annotations

import json
import sqlite3
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .capture import CaptureSession, CapturedQuery


@dataclass
class ReplayDiff:
    """Difference found during replay."""

    query_index: int
    sql: str
    field: str  # 'rows_affected', 'result_sample', 'error'
    expected: Any
    actual: Any


@dataclass
class ReplayResult:
    """Result of replaying a capture session."""

    total_queries: int = 0
    replayed: int = 0
    skipped: int = 0
    errors: int = 0
    diffs: list[ReplayDiff] = field(default_factory=list)
    total_duration_ms: float = 0.0
    original_duration_ms: float = 0.0

    @property
    def passed(self) -> bool:
        return self.errors == 0 and len(self.diffs) == 0

    def summary(self) -> str:
        lines = [
            f"Replay Summary",
            f"{'=' * 40}",
            f"Total queries: {self.total_queries}",
            f"Replayed:      {self.replayed}",
            f"Skipped:       {self.skipped}",
            f"Errors:        {self.errors}",
            f"Diffs found:   {len(self.diffs)}",
            f"Original time: {self.original_duration_ms:.1f}ms",
            f"Replay time:   {self.total_duration_ms:.1f}ms",
            f"Status:        {'PASS' if self.passed else 'FAIL'}",
        ]

        if self.diffs:
            lines.append(f"\nDifferences:")
            for d in self.diffs[:20]:  # Limit output
                lines.append(f"  Query #{d.query_index}: {d.field}")
                lines.append(f"    SQL: {d.sql[:80]}...")
                lines.append(f"    Expected: {d.expected}")
                lines.append(f"    Actual:   {d.actual}")

        return "\n".join(lines)


def _normalize_value(val: Any) -> Any:
    """Normalize values for comparison (handle type differences across DBs)."""
    if val is None:
        return None
    if isinstance(val, (int, float)):
        return val
    if isinstance(val, dict):
        return {k: _normalize_value(v) for k, v in sorted(val.items())}
    if isinstance(val, (list, tuple)):
        return [_normalize_value(v) for v in val]
    return str(val)


def _is_read_query(sql: str) -> bool:
    """Check if a SQL query is a read (SELECT/WITH) query."""
    stripped = sql.strip().upper()
    return stripped.startswith("SELECT") or stripped.startswith("WITH")


def _is_ddl(sql: str) -> bool:
    """Check if a SQL query is DDL (CREATE, DROP, ALTER)."""
    stripped = sql.strip().upper()
    return any(stripped.startswith(kw) for kw in ("CREATE", "DROP", "ALTER", "TRUNCATE"))


def replay_sqlite(
    session: CaptureSession,
    db_path: str = ":memory:",
    skip_ddl: bool = False,
    compare_results: bool = True,
) -> ReplayResult:
    """Replay captured queries against a SQLite database.

    Args:
        session: The captured session to replay.
        db_path: Path to the SQLite database (use :memory: for ephemeral).
        skip_ddl: Skip DDL statements (CREATE, DROP, ALTER).
        compare_results: Compare result samples with original capture.

    Returns:
        ReplayResult with comparison details.
    """
    result = ReplayResult(
        total_queries=session.query_count,
        original_duration_ms=session.total_duration_ms,
    )

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    for i, query in enumerate(session.queries):
        if skip_ddl and _is_ddl(query.sql):
            result.skipped += 1
            continue

        start = time.perf_counter()
        try:
            if query.params:
                cursor.execute(query.sql, query.params)
            else:
                cursor.execute(query.sql)

            duration = (time.perf_counter() - start) * 1000
            result.total_duration_ms += duration
            result.replayed += 1

            # Compare row counts for write queries
            if not _is_read_query(query.sql) and query.rows_affected > 0:
                actual_affected = cursor.rowcount if cursor.rowcount >= 0 else 0
                if actual_affected != query.rows_affected:
                    result.diffs.append(ReplayDiff(
                        query_index=i, sql=query.sql, field="rows_affected",
                        expected=query.rows_affected, actual=actual_affected,
                    ))

            # Compare result samples for read queries
            if compare_results and _is_read_query(query.sql) and query.result_sample:
                rows = cursor.fetchmany(len(query.result_sample))
                if cursor.description:
                    columns = [d[0] for d in cursor.description]
                    actual_sample = [dict(zip(columns, row)) for row in rows]

                    expected_norm = _normalize_value(query.result_sample)
                    actual_norm = _normalize_value(actual_sample)

                    if expected_norm != actual_norm:
                        result.diffs.append(ReplayDiff(
                            query_index=i, sql=query.sql, field="result_sample",
                            expected=query.result_sample, actual=actual_sample,
                        ))

            conn.commit()

        except Exception as exc:
            duration = (time.perf_counter() - start) * 1000
            result.total_duration_ms += duration
            result.errors += 1
            result.diffs.append(ReplayDiff(
                query_index=i, sql=query.sql, field="error",
                expected="success", actual=str(exc),
            ))

    conn.close()
    return result


def replay_from_file(
    capture_path: str | Path,
    db_path: str = ":memory:",
    **kwargs,
) -> ReplayResult:
    """Load a capture file and replay it.

    Args:
        capture_path: Path to the JSONL capture file.
        db_path: Path to the replay database.
        **kwargs: Additional arguments passed to replay_sqlite.

    Returns:
        ReplayResult with comparison details.
    """
    session = CaptureSession.load(capture_path)
    return replay_sqlite(session, db_path, **kwargs)
