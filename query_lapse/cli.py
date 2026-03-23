"""CLI for query-lapse: capture, replay, and analyze database queries."""

from __future__ import annotations

from pathlib import Path

import click

from .capture import CaptureSession, capture_sqlite
from .anonymizer import anonymize_file, AnonymizerConfig
from .replay import replay_from_file, replay_sqlite
from .fixtures import generate_sql_fixtures, generate_json_snapshots, generate_pytest_fixtures
from .detector import analyze


@click.group()
@click.version_option()
def cli():
    """query-lapse: Record DB queries and replay them as deterministic test fixtures."""


@cli.command()
@click.option("--dsn", default=None, help="PostgreSQL DSN (postgresql://user:pass@host/db)")
@click.option("--sqlite", "sqlite_path", default=None, help="SQLite database path")
@click.option("-o", "--output", default="capture.jsonl", help="Output JSONL file path")
@click.option("--demo", is_flag=True, help="Run a demo capture with an in-memory SQLite database")
def capture(dsn: str | None, sqlite_path: str | None, output: str, demo: bool):
    """Capture SQL queries from a database connection.

    Use --demo to see a working example with SQLite in-memory.
    """
    if demo:
        click.echo("Running demo capture with in-memory SQLite...")
        with capture_sqlite(":memory:") as (conn, session):
            cursor = conn.cursor()

            # Create schema
            cursor.execute("""
                CREATE TABLE users (
                    id INTEGER PRIMARY KEY,
                    name TEXT NOT NULL,
                    email TEXT UNIQUE,
                    phone TEXT,
                    ip_address TEXT
                )
            """)

            cursor.execute("""
                CREATE TABLE orders (
                    id INTEGER PRIMARY KEY,
                    user_id INTEGER REFERENCES users(id),
                    product TEXT,
                    amount REAL,
                    created_at TEXT
                )
            """)

            # Insert test data
            users = [
                (1, "Alice Johnson", "alice@example.com", "555-123-4567", "192.168.1.10"),
                (2, "Bob Smith", "bob.smith@company.org", "555-987-6543", "10.0.0.42"),
                (3, "Charlie Brown", "charlie@email.net", "555-456-7890", "172.16.0.5"),
            ]
            cursor.executemany("INSERT INTO users VALUES (?, ?, ?, ?, ?)", users)

            orders = [
                (1, 1, "Widget", 29.99, "2026-01-15"),
                (2, 1, "Gadget", 49.99, "2026-01-20"),
                (3, 2, "Widget", 29.99, "2026-02-01"),
                (4, 3, "Thingamajig", 99.99, "2026-02-10"),
            ]
            cursor.executemany("INSERT INTO orders VALUES (?, ?, ?, ?, ?)", orders)
            conn.commit()

            # Run some queries
            cursor.execute("SELECT * FROM users WHERE id = ?", (1,))
            cursor.execute("SELECT * FROM users WHERE id = ?", (2,))
            cursor.execute("SELECT * FROM users WHERE id = ?", (3,))

            cursor.execute("""
                SELECT u.name, COUNT(o.id) as order_count, SUM(o.amount) as total
                FROM users u
                LEFT JOIN orders o ON u.id = o.user_id
                GROUP BY u.id
            """)

            cursor.execute("SELECT * FROM orders WHERE amount > ?", (30.0,))

        session.save(output)
        click.echo(f"Captured {session.query_count} queries to {output}")
        click.echo(f"Total duration: {session.total_duration_ms:.1f}ms")
        return

    if sqlite_path:
        click.echo(f"Capturing from SQLite: {sqlite_path}")
        click.echo("Press Ctrl+C to stop capture and save.")
        # For SQLite, wrap and run interactively
        with capture_sqlite(sqlite_path) as (conn, session):
            cursor = conn.cursor()
            click.echo("Connected. Enter SQL queries (empty line to quit):")
            while True:
                try:
                    sql = click.prompt("SQL", default="", show_default=False)
                    if not sql.strip():
                        break
                    cursor.execute(sql)
                    if cursor.description:
                        columns = [d[0] for d in cursor.description]
                        rows = cursor.fetchall()
                        click.echo(f"  Columns: {columns}")
                        for row in rows[:10]:
                            click.echo(f"  {list(row)}")
                        click.echo(f"  ({len(rows)} rows)")
                    conn.commit()
                except Exception as e:
                    click.echo(f"  Error: {e}")

        session.save(output)
        click.echo(f"\nCaptured {session.query_count} queries to {output}")

    elif dsn:
        click.echo(f"Capturing from PostgreSQL: {dsn[:30]}...")
        try:
            from .capture import capture_postgres
            with capture_postgres(dsn) as (conn, session):
                cursor = conn.cursor()
                click.echo("Connected. Enter SQL queries (empty line to quit):")
                while True:
                    try:
                        sql = click.prompt("SQL", default="", show_default=False)
                        if not sql.strip():
                            break
                        cursor.execute(sql)
                        conn.commit()
                    except Exception as e:
                        click.echo(f"  Error: {e}")
                        conn.rollback()
            session.save(output)
            click.echo(f"\nCaptured {session.query_count} queries to {output}")
        except ImportError:
            click.echo("Error: psycopg2 required. Install with: pip install query-lapse[postgres]")
    else:
        click.echo("Specify --sqlite, --dsn, or --demo. See --help for details.")


@cli.command()
@click.argument("fixtures_path", type=click.Path(exists=True))
@click.option("--db", default=":memory:", help="SQLite database path for replay")
@click.option("--no-compare", is_flag=True, help="Skip result comparison")
def replay(fixtures_path: str, db: str, no_compare: bool):
    """Replay captured queries against a test database.

    FIXTURES_PATH is a JSONL file from the capture command.
    """
    click.echo(f"Replaying {fixtures_path} against {db}...")
    result = replay_from_file(fixtures_path, db_path=db, compare_results=not no_compare)
    click.echo(result.summary())


@cli.command()
@click.argument("input_path", type=click.Path(exists=True))
@click.option("-o", "--output", default=None, help="Output path (default: input.anon.jsonl)")
@click.option("--salt", default="query-lapse-default-salt", help="Salt for consistent anonymization")
@click.option("--no-emails", is_flag=True, help="Skip email scrubbing")
@click.option("--no-phones", is_flag=True, help="Skip phone scrubbing")
@click.option("--no-ips", is_flag=True, help="Skip IP scrubbing")
def anonymize(input_path: str, output: str | None, salt: str,
              no_emails: bool, no_phones: bool, no_ips: bool):
    """Anonymize PII in captured query data.

    Replaces emails, phones, IPs, UUIDs, and credit card numbers with
    consistent fake data (same input always maps to same fake output).
    """
    config = AnonymizerConfig(
        salt=salt,
        scrub_emails=not no_emails,
        scrub_phones=not no_phones,
        scrub_ips=not no_ips,
    )

    output_path = anonymize_file(input_path, output, config)
    click.echo(f"Anonymized: {input_path} -> {output_path}")

    # Show a sample
    session = CaptureSession.load(output_path)
    if session.queries:
        click.echo(f"\nSample anonymized query:")
        q = session.queries[0]
        click.echo(f"  SQL: {q.sql[:100]}...")
        if q.params:
            click.echo(f"  Params: {q.params}")


@cli.command()
@click.argument("capture_path", type=click.Path(exists=True))
@click.option("-o", "--output", default="fixtures/", help="Output directory")
@click.option("-f", "--format", "fmt", type=click.Choice(["sql", "json", "pytest", "all"]),
              default="all", help="Output format")
def export(capture_path: str, output: str, fmt: str):
    """Export captured queries as test fixtures.

    Generates SQL files, JSON snapshots, and/or pytest test templates.
    """
    session = CaptureSession.load(capture_path)
    click.echo(f"Loaded {session.query_count} queries from {capture_path}")

    files = []
    if fmt in ("sql", "all"):
        files.extend(generate_sql_fixtures(session, f"{output}/sql"))
    if fmt in ("json", "all"):
        files.extend(generate_json_snapshots(session, f"{output}/snapshots"))
    if fmt in ("pytest", "all"):
        files.append(generate_pytest_fixtures(session, f"{output}/test_queries.py"))

    click.echo(f"\nGenerated {len(files)} files:")
    for f in files:
        click.echo(f"  - {f}")


@cli.command()
@click.argument("capture_path", type=click.Path(exists=True))
@click.option("--slow-threshold", default=100.0, help="Slow query threshold in ms")
def detect(capture_path: str, slow_threshold: float):
    """Analyze captured queries for anti-patterns.

    Detects N+1 queries, slow queries, duplicates, and missing WHERE clauses.
    """
    session = CaptureSession.load(capture_path)
    report = analyze(session, slow_threshold_ms=slow_threshold)
    click.echo(report.summary())


if __name__ == "__main__":
    cli()
