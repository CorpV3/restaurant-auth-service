"""add pos_passcode to users

Revision ID: 002
Revises: a1b2c3d4e5f6
Create Date: 2026-03-28
"""
from alembic import op
import sqlalchemy as sa

revision = '002'
down_revision = 'a1b2c3d4e5f6'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('users', sa.Column('pos_passcode', sa.String(255), nullable=True))


def downgrade():
    op.drop_column('users', 'pos_passcode')
