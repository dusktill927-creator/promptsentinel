"""Record the target's last response on every probe run.

Nullable, because existing rows predate it and there is nothing to backfill: the
responses were never captured. A clean probe run with no recorded output stays
unauditable for scans that already happened, and becomes auditable from here on.

Revision ID: adc2ec4887dc
Revises: 53f2707dd0e3
Create Date: 2026-09-16 20:04:56.506469
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "adc2ec4887dc"
down_revision: str | None = "53f2707dd0e3"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("probe_runs", schema=None) as batch_op:
        batch_op.add_column(sa.Column("last_response", sa.Text(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("probe_runs", schema=None) as batch_op:
        batch_op.drop_column("last_response")
