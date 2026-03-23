"""PII detection and consistent anonymization."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .capture import CaptureSession, CapturedQuery


# Fake data pools keyed by PII type
_FAKE_FIRST_NAMES = [
    "Alex", "Jordan", "Taylor", "Morgan", "Casey", "Riley", "Quinn",
    "Avery", "Parker", "Sage", "Rowan", "Blake", "Drew", "Skyler",
    "Hayden", "Dakota", "Emerson", "Finley", "Harley", "Jamie",
]

_FAKE_LAST_NAMES = [
    "Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia",
    "Miller", "Davis", "Rodriguez", "Martinez", "Anderson", "Taylor",
    "Thomas", "Moore", "Jackson", "Martin", "Lee", "Clark", "Hall", "Young",
]

_FAKE_DOMAINS = [
    "example.com", "test.org", "sample.net", "demo.io", "mock.dev",
]


@dataclass
class AnonymizerConfig:
    """Configuration for PII anonymization."""

    scrub_emails: bool = True
    scrub_phones: bool = True
    scrub_ips: bool = True
    scrub_names: bool = True
    scrub_uuids: bool = True
    scrub_credit_cards: bool = True
    salt: str = "query-lapse-default-salt"


class Anonymizer:
    """Deterministic PII anonymizer using hash-based mapping.

    Same input always produces the same fake output within a session,
    ensuring referential integrity across anonymized data.
    """

    def __init__(self, config: AnonymizerConfig | None = None):
        self.config = config or AnonymizerConfig()
        self._mapping: dict[str, str] = {}

    def _consistent_hash(self, value: str, pool_size: int) -> int:
        """Hash a value to a consistent index."""
        h = hashlib.sha256(f"{self.config.salt}:{value}".encode()).hexdigest()
        return int(h[:8], 16) % pool_size

    def _get_or_create(self, original: str, category: str, generator) -> str:
        """Get existing mapping or create a new one."""
        key = f"{category}:{original}"
        if key not in self._mapping:
            self._mapping[key] = generator(original)
        return self._mapping[key]

    def _fake_email(self, original: str) -> str:
        idx = self._consistent_hash(original, len(_FAKE_FIRST_NAMES))
        domain_idx = self._consistent_hash(original + "domain", len(_FAKE_DOMAINS))
        name = _FAKE_FIRST_NAMES[idx].lower()
        num = self._consistent_hash(original, 999)
        return f"{name}{num}@{_FAKE_DOMAINS[domain_idx]}"

    def _fake_phone(self, original: str) -> str:
        h = self._consistent_hash(original, 10_000_000)
        return f"+1-555-{h % 10000:04d}"

    def _fake_ip(self, original: str) -> str:
        h = hashlib.sha256(f"{self.config.salt}:ip:{original}".encode()).hexdigest()
        parts = [str(int(h[i:i+2], 16)) for i in range(0, 8, 2)]
        parts[0] = "10"  # Always private range
        return ".".join(parts)

    def _fake_uuid(self, original: str) -> str:
        h = hashlib.sha256(f"{self.config.salt}:uuid:{original}".encode()).hexdigest()
        return f"{h[:8]}-{h[8:12]}-4{h[13:16]}-a{h[17:20]}-{h[20:32]}"

    def _fake_name(self, original: str) -> str:
        first_idx = self._consistent_hash(original, len(_FAKE_FIRST_NAMES))
        last_idx = self._consistent_hash(original + "last", len(_FAKE_LAST_NAMES))
        return f"{_FAKE_FIRST_NAMES[first_idx]} {_FAKE_LAST_NAMES[last_idx]}"

    def _fake_credit_card(self, original: str) -> str:
        h = self._consistent_hash(original, 10**12)
        return f"4111-{h % 10000:04d}-{(h // 10000) % 10000:04d}-{(h // 10**8) % 10000:04d}"

    # Regex patterns for PII detection
    _EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
    _PHONE_RE = re.compile(r"(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}")
    _IP_RE = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")
    _UUID_RE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.I)
    _CC_RE = re.compile(r"\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b")

    def scrub_string(self, text: str) -> str:
        """Scrub PII from a string, replacing with consistent fakes."""
        if not isinstance(text, str):
            return text

        if self.config.scrub_uuids:
            text = self._UUID_RE.sub(
                lambda m: self._get_or_create(m.group(), "uuid", self._fake_uuid), text
            )
        if self.config.scrub_emails:
            text = self._EMAIL_RE.sub(
                lambda m: self._get_or_create(m.group(), "email", self._fake_email), text
            )
        if self.config.scrub_credit_cards:
            text = self._CC_RE.sub(
                lambda m: self._get_or_create(m.group(), "cc", self._fake_credit_card), text
            )
        if self.config.scrub_phones:
            text = self._PHONE_RE.sub(
                lambda m: self._get_or_create(m.group(), "phone", self._fake_phone), text
            )
        if self.config.scrub_ips:
            text = self._IP_RE.sub(
                lambda m: self._get_or_create(m.group(), "ip", self._fake_ip), text
            )

        return text

    def scrub_value(self, value: Any) -> Any:
        """Scrub PII from any value (string, list, dict, or primitive)."""
        if isinstance(value, str):
            return self.scrub_string(value)
        if isinstance(value, dict):
            return {k: self.scrub_value(v) for k, v in value.items()}
        if isinstance(value, (list, tuple)):
            return [self.scrub_value(v) for v in value]
        return value

    def scrub_query(self, query: CapturedQuery) -> CapturedQuery:
        """Scrub PII from a captured query."""
        return CapturedQuery(
            sql=self.scrub_string(query.sql),
            params=self.scrub_value(query.params),
            duration_ms=query.duration_ms,
            rows_affected=query.rows_affected,
            result_sample=self.scrub_value(query.result_sample),
            timestamp=query.timestamp,
            source=query.source,
        )

    def scrub_session(self, session: CaptureSession) -> CaptureSession:
        """Scrub PII from all queries in a session."""
        scrubbed = CaptureSession(
            started_at=session.started_at,
            dsn=self.scrub_string(session.dsn),
        )
        scrubbed.queries = [self.scrub_query(q) for q in session.queries]
        return scrubbed

    @property
    def mapping_table(self) -> dict[str, str]:
        """Return the current PII mapping table (for debugging/audit)."""
        return dict(self._mapping)


def anonymize_file(
    input_path: str | Path,
    output_path: str | Path | None = None,
    config: AnonymizerConfig | None = None,
) -> Path:
    """Anonymize a JSONL capture file.

    Args:
        input_path: Path to the input JSONL file.
        output_path: Path for the anonymized output. Defaults to input with '.anon' suffix.
        config: Anonymizer configuration.

    Returns:
        Path to the anonymized file.
    """
    input_path = Path(input_path)
    if output_path is None:
        output_path = input_path.with_suffix(".anon.jsonl")
    else:
        output_path = Path(output_path)

    session = CaptureSession.load(input_path)
    anon = Anonymizer(config)
    scrubbed = anon.scrub_session(session)
    scrubbed.save(output_path)

    return output_path
