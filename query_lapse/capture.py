"""SQL query capture via connection wrapping."""

from __future__ import annotations

import json
import sqlite3
import time
from contextlib import contextmanager
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Iterator


@dataclass
class CapturedQuery:
    """A single captured SQL query with metadata."""

    sql: str
    params: list[Any] | None = None
    duration_ms: float = 0.0
    rows_affected: int = 0
    result_sample: list[dict] | None = None
    timestamp: float = 0.0
    source: str = ""  # 'sqlite' or 'postgres'

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class CaptureSession:
    """A recording session containing multiple captured queries."""

    queries: list[CapturedQuery] = field(default_factory=list)
    started_at: float = 0.0
    dsn: str = ""

    def save(self, path: str | Path) -> None:
        """Save captured queries to a JSONL file."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w") as f:
            for q in self.queries:
                f.write(json.dumps(q.to_dict(), default=str) + "\n")

    @classmethod
    def load(cls, path: str | Path) -> CaptureSession:
        """Load captured queries from a JSONL file."""
        session = cls()
        with open(path) as f:
            for line in f:
                line = line.strip()
                if line:
                    data = json.loads(line)
                    session.queries.append(CapturedQuery(**data))
        return session

    @property
    def total_duration_ms(self) -> float:
        return sum(q.duration_ms for q in self.queries)

    @property
    def query_count(self) -> int:
        return len(self.queries)


class CaptureCursor:
    """Wraps a DB-API 2.0 cursor to capture queries."""

    def __init__(self, real_cursor: Any, session: CaptureSession, source: str = "unknown",
                 sample_rows: int = 5):
        self._cursor = real_cursor
        self._session = session
        self._source = source
        self._sample_rows = sample_rows

    def execute(self, sql: str, params: Any = None) -> Any:
        start = time.perf_counter()
        try:
            if params:
                result = self._cursor.execute(sql, params)
            else:
                result = self._cursor.execute(sql)
            duration = (time.perf_counter() - start) * 1000

            rows_affected = self._cursor.rowcount if self._cursor.rowcount >= 0 else 0

            # Sample results for SELECT queries
            sample = None
            sql_upper = sql.strip().upper()
            if sql_upper.startswith("SELECT") or sql_upper.startswith("WITH"):
                try:
                    rows = self._cursor.fetchmany(self._sample_rows)
                    if rows and self._cursor.description:
                        columns = [d[0] for d in self._cursor.description]
                        sample = [dict(zip(columns, row)) for row in rows]
                        # Re-execute since fetchmany consumed rows
                        if params:
                            self._cursor.execute(sql, params)
                        else:
                            self._cursor.execute(sql)
                except Exception:
                    pass

            param_list = list(params) if params and not isinstance(params, (list, tuple)) else (
                list(params) if params else None
            )

            self._session.queries.append(CapturedQuery(
                sql=sql,
                params=param_list,
                duration_ms=round(duration, 3),
                rows_affected=rows_affected,
                result_sample=sample,
                timestamp=time.time(),
                source=self._source,
            ))

            return result
        except Exception as exc:
            duration = (time.perf_counter() - start) * 1000
            self._session.queries.append(CapturedQuery(
                sql=sql,
                params=list(params) if params else None,
                duration_ms=round(duration, 3),
                rows_affected=0,
                timestamp=time.time(),
                source=f"{self._source}:ERROR:{type(exc).__name__}",
            ))
            raise

    def executemany(self, sql: str, param_list: list) -> Any:
        start = time.perf_counter()
        result = self._cursor.executemany(sql, param_list)
        duration = (time.perf_counter() - start) * 1000

        self._session.queries.append(CapturedQuery(
            sql=sql,
            params=[f"<batch of {len(param_list)}>"],
            duration_ms=round(duration, 3),
            rows_affected=self._cursor.rowcount if self._cursor.rowcount >= 0 else 0,
            timestamp=time.time(),
            source=self._source,
        ))
        return result

    def fetchone(self) -> Any:
        return self._cursor.fetchone()

    def fetchall(self) -> Any:
        return self._cursor.fetchall()

    def fetchmany(self, size: int | None = None) -> Any:
        return self._cursor.fetchmany(size) if size else self._cursor.fetchmany()

    @property
    def description(self):
        return self._cursor.description

    @property
    def rowcount(self):
        return self._cursor.rowcount

    def close(self):
        return self._cursor.close()

    def __iter__(self):
        return iter(self._cursor)

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


class CaptureConnection:
    """Wraps a DB-API 2.0 connection to capture all queries."""

    def __init__(self, real_connection: Any, session: CaptureSession, source: str = "unknown"):
        self._conn = real_connection
        self._session = session
        self._source = source

    def cursor(self, *args, **kwargs) -> CaptureCursor:
        real_cursor = self._conn.cursor(*args, **kwargs)
        return CaptureCursor(real_cursor, self._session, self._source)

    def commit(self):
        return self._conn.commit()

    def rollback(self):
        return self._conn.rollback()

    def close(self):
        return self._conn.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self._conn.__exit__(*args)


@contextmanager
def capture_sqlite(db_path: str = ":memory:") -> Iterator[tuple[CaptureConnection, CaptureSession]]:
    """Context manager that wraps a SQLite connection for capture.

    Usage:
        with capture_sqlite("mydb.sqlite") as (conn, session):
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users")
        session.save("fixtures/queries.jsonl")
    """
    session = CaptureSession(started_at=time.time(), dsn=f"sqlite:///{db_path}")
    real_conn = sqlite3.connect(db_path)
    real_conn.row_factory = sqlite3.Row
    wrapped = CaptureConnection(real_conn, session, source="sqlite")
    try:
        yield wrapped, session
    finally:
        real_conn.close()


@contextmanager
def capture_postgres(dsn: str) -> Iterator[tuple[CaptureConnection, CaptureSession]]:
    """Context manager that wraps a PostgreSQL connection for capture.

    Requires psycopg2 to be installed.

    Usage:
        with capture_postgres("postgresql://user:pass@localhost/db") as (conn, session):
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users")
        session.save("fixtures/queries.jsonl")
    """
    try:
        import psycopg2
    except ImportError:
        raise ImportError("psycopg2 is required for PostgreSQL capture. Install with: pip install query-lapse[postgres]")

    session = CaptureSession(started_at=time.time(), dsn=dsn)
    real_conn = psycopg2.connect(dsn)
    wrapped = CaptureConnection(real_conn, session, source="postgres")
    try:
        yield wrapped, session
    finally:
        real_conn.close()
