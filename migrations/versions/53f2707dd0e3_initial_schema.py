"""Initial schema: scans, probe_runs, findings.

Matches the ORM models as of v0.1.0. ``tests/integration/test_schema_migrations.py``
asserts that running every migration produces a schema identical to
``Base.metadata`` -- so a model change without a matching migration fails CI rather
than surfacing as a production error.

Revision ID: 53f2707dd0e3
Revises:
Create Date: 2026-09-16 15:43:11.271982
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "53f2707dd0e3"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "scans",
        sa.Column("id", sa.String(length=32), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("target_kind", sa.String(length=50), nullable=False),
        sa.Column("target_description", sa.String(length=500), nullable=False),
        sa.Column("target_spec_redacted", sa.JSON(), nullable=False),
        sa.Column("requested_probe_ids", sa.JSON(), nullable=False),
        sa.Column("options", sa.JSON(), nullable=False),
        sa.Column("authorization_confirmed", sa.Boolean(), nullable=False),
        sa.Column("authorized_by", sa.String(length=200), nullable=False),
        sa.Column("authorization_statement", sa.Text(), nullable=False),
        sa.Column("authorization_reference", sa.String(length=200), nullable=True),
        sa.Column("authorized_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("webhook_url", sa.String(length=2000), nullable=True),
        sa.Column("webhook_status", sa.String(length=50), nullable=True),
        sa.Column("canaries_seeded", sa.JSON(), nullable=False),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    with op.batch_alter_table("scans", schema=None) as batch_op:
        batch_op.create_index(batch_op.f("ix_scans_created_at"), ["created_at"], unique=False)
        batch_op.create_index(batch_op.f("ix_scans_status"), ["status"], unique=False)

    op.create_table(
        "findings",
        sa.Column("id", sa.String(length=32), nullable=False),
        sa.Column("scan_id", sa.String(length=32), nullable=False),
        sa.Column("probe_id", sa.String(length=100), nullable=False),
        sa.Column("category", sa.String(length=50), nullable=False),
        sa.Column("title", sa.String(length=300), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("severity", sa.String(length=20), nullable=False),
        sa.Column("confidence", sa.String(length=20), nullable=False),
        sa.Column("evidence", sa.JSON(), nullable=False),
        sa.Column("proof", sa.JSON(), nullable=True),
        sa.Column("signals", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    with op.batch_alter_table("findings", schema=None) as batch_op:
        batch_op.create_index(batch_op.f("ix_findings_confidence"), ["confidence"], unique=False)
        batch_op.create_index(
            "ix_findings_scan_confidence", ["scan_id", "confidence"], unique=False
        )
        batch_op.create_index(batch_op.f("ix_findings_scan_id"), ["scan_id"], unique=False)

    op.create_table(
        "probe_runs",
        sa.Column("id", sa.String(length=32), nullable=False),
        sa.Column("scan_id", sa.String(length=32), nullable=False),
        sa.Column("probe_id", sa.String(length=100), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False),
        sa.Column("duration_ms", sa.Integer(), nullable=False),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("detail", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    with op.batch_alter_table("probe_runs", schema=None) as batch_op:
        batch_op.create_index(batch_op.f("ix_probe_runs_scan_id"), ["scan_id"], unique=False)


def downgrade() -> None:
    with op.batch_alter_table("probe_runs", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_probe_runs_scan_id"))

    op.drop_table("probe_runs")
    with op.batch_alter_table("findings", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_findings_scan_id"))
        batch_op.drop_index("ix_findings_scan_confidence")
        batch_op.drop_index(batch_op.f("ix_findings_confidence"))

    op.drop_table("findings")
    with op.batch_alter_table("scans", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_scans_status"))
        batch_op.drop_index(batch_op.f("ix_scans_created_at"))

    op.drop_table("scans")
