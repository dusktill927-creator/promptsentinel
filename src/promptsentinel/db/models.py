"""SQLAlchemy ORM models.

Two conventions here are deliberate and worth copying:

* **Enums are stored as plain strings, not native DB enum types.** Native enums make
  adding a probe category a schema migration with a table lock on Postgres. The
  domain ``StrEnum`` is the source of truth; the column is just text.
* **String UUID primary keys.** Portable across SQLite and Postgres, safe to expose
  in URLs, and no auto-increment counter leaking how many scans you have run.

These rows are *not* the domain models. ``db/repository.py`` translates between them,
which is the seam that lets the schema change without touching probe code.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import JSON, DateTime, ForeignKey, Index, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

from promptsentinel.core.models import ScanStatus, new_id, utcnow


class Base(DeclarativeBase):
    """Declarative base. ``type_annotation_map`` keeps column types in one place."""

    type_annotation_map = {  # noqa: RUF012
        dict[str, Any]: JSON,
        list[Any]: JSON,
        datetime: DateTime(timezone=True),
    }


class ScanRow(Base):
    """One scan job.

    The authorization attestation is stored inline rather than in a side table: it is
    the record that this scan was permitted, and it must be impossible to have a scan
    row without one.
    """

    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    status: Mapped[str] = mapped_column(String(20), default=ScanStatus.PENDING.value, index=True)

    target_kind: Mapped[str] = mapped_column(String(50))
    target_description: Mapped[str] = mapped_column(String(500))
    target_spec_redacted: Mapped[dict[str, Any]] = mapped_column(default=dict)
    """Credentials are stripped before this is written. See ``repository.create_scan``."""

    requested_probe_ids: Mapped[list[Any]] = mapped_column(default=list)
    options: Mapped[dict[str, Any]] = mapped_column(default=dict)

    # --- authorization attestation (audit record) ---
    authorization_confirmed: Mapped[bool] = mapped_column(default=False)
    authorized_by: Mapped[str] = mapped_column(String(200))
    authorization_statement: Mapped[str] = mapped_column(Text)
    authorization_reference: Mapped[str | None] = mapped_column(String(200), default=None)
    authorized_at: Mapped[datetime] = mapped_column(default=utcnow)

    webhook_url: Mapped[str | None] = mapped_column(String(2000), default=None)
    webhook_status: Mapped[str | None] = mapped_column(String(50), default=None)

    canaries_seeded: Mapped[list[Any]] = mapped_column(default=list)
    """Redacted record of every synthetic secret planted, so an operator can audit it."""

    error: Mapped[str | None] = mapped_column(Text, default=None)
    created_at: Mapped[datetime] = mapped_column(default=utcnow, index=True)
    started_at: Mapped[datetime | None] = mapped_column(default=None)
    finished_at: Mapped[datetime | None] = mapped_column(default=None)

    probe_runs: Mapped[list[ProbeRunRow]] = relationship(
        back_populates="scan", cascade="all, delete-orphan", lazy="selectin"
    )
    findings: Mapped[list[FindingRow]] = relationship(
        back_populates="scan", cascade="all, delete-orphan", lazy="selectin"
    )


class ProbeRunRow(Base):
    """The outcome of one probe within one scan.

    Stored even when a probe finds nothing, because "ran and found nothing" and
    "never ran" are different facts and a report that conflates them is misleading.
    """

    __tablename__ = "probe_runs"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    probe_id: Mapped[str] = mapped_column(String(100))
    status: Mapped[str] = mapped_column(String(20))
    attempts: Mapped[int] = mapped_column(default=0)
    duration_ms: Mapped[int] = mapped_column(default=0)
    error: Mapped[str | None] = mapped_column(Text, default=None)
    detail: Mapped[str | None] = mapped_column(Text, default=None)
    created_at: Mapped[datetime] = mapped_column(default=utcnow)

    scan: Mapped[ScanRow] = relationship(back_populates="probe_runs")


class FindingRow(Base):
    """A single reported issue."""

    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    probe_id: Mapped[str] = mapped_column(String(100))
    category: Mapped[str] = mapped_column(String(50))
    title: Mapped[str] = mapped_column(String(300))
    description: Mapped[str] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(String(20))
    confidence: Mapped[str] = mapped_column(String(20), index=True)
    evidence: Mapped[dict[str, Any]] = mapped_column(default=dict)
    proof: Mapped[dict[str, Any] | None] = mapped_column(JSON, default=None)
    signals: Mapped[list[Any]] = mapped_column(default=list)
    created_at: Mapped[datetime] = mapped_column(default=utcnow)

    scan: Mapped[ScanRow] = relationship(back_populates="findings")

    __table_args__ = (Index("ix_findings_scan_confidence", "scan_id", "confidence"),)
