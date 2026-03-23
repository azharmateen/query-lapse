# query-lapse

**Record database queries and replay them as deterministic test fixtures with automatic PII scrubbing.**

Point it at your database, run your app, and get back anonymized query fixtures you can commit to your test suite. Catches N+1 queries and slow queries as a bonus.

## Demo

```bash
# Capture queries (demo mode with built-in sample data)
query-lapse capture --demo -o queries.jsonl

# Scrub PII (emails, phones, IPs, UUIDs)
query-lapse anonymize queries.jsonl

# Export as test fixtures
query-lapse export queries.anon.jsonl -o fixtures/

# Detect N+1 and slow queries
query-lapse detect queries.jsonl

# Replay against a test database
query-lapse replay queries.jsonl --db test.sqlite
```

## Quickstart

```bash
pip install query-lapse

# Option 1: Capture from SQLite
query-lapse capture --sqlite myapp.db -o queries.jsonl

# Option 2: Capture from PostgreSQL
pip install query-lapse[postgres]
query-lapse capture --dsn "postgresql://user:pass@localhost/mydb" -o queries.jsonl

# Option 3: Try the built-in demo
query-lapse capture --demo
```

## Features

- **Zero-config capture**: Wraps any DB-API 2.0 connection (SQLite, PostgreSQL) to record all queries with timing and results
- **PII scrubbing**: Detects and replaces emails, phone numbers, IPs, UUIDs, and credit card numbers with consistent fakes (same input always produces the same output -- referential integrity preserved)
- **Deterministic replay**: Replay captured queries against a test database and diff the results
- **Test fixture generation**: Outputs SQL files, JSON snapshots, and complete pytest test templates
- **Anti-pattern detection**: Catches N+1 queries, slow queries, exact duplicates, and missing WHERE clauses
- **JSONL format**: Human-readable, git-friendly, easy to pipe and filter

## Programmatic Usage

```python
from query_lapse.capture import capture_sqlite

# Wrap your connection
with capture_sqlite("myapp.db") as (conn, session):
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE active = ?", (True,))
    users = cursor.fetchall()

# Save captured queries
session.save("fixtures/queries.jsonl")

# Anonymize
from query_lapse.anonymizer import Anonymizer
anon = Anonymizer()
clean_session = anon.scrub_session(session)
clean_session.save("fixtures/queries.anon.jsonl")

# Detect issues
from query_lapse.detector import analyze
report = analyze(session)
print(report.summary())
```

## Architecture

```
Database Connection
       |
   CaptureCursor (wraps DB-API 2.0)
       |
   CaptureSession (JSONL on disk)
       |
   +---+---+---+---+
   |   |   |   |   |
  Anon Replay Export Detect
   |     |     |      |
  PII  Diff   SQL   N+1/Slow
 scrub       JSON   Duplicate
             pytest
```

1. **Capture** wraps your database cursor, logging every `execute()` with SQL, params, timing, and result samples
2. **Anonymizer** uses hash-based mapping for deterministic PII replacement (same email always becomes the same fake)
3. **Replay** re-executes captured queries and diffs results against the originals
4. **Fixtures** generates ready-to-use SQL, JSON snapshots, and pytest test files
5. **Detector** analyzes query patterns to find N+1, slow queries, duplicates, and dangerous operations

## Contributing

1. Fork the repo
2. Create a feature branch
3. Run `python -m pytest` to ensure tests pass
4. Submit a PR

## License

MIT
