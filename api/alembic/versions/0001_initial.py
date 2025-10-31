"""initial schema

Revision ID: 0001_initial
Revises:
Create Date: 2025-10-30
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '0001_initial'
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
	op.create_table(
		'targets',
		sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
		sa.Column('url', sa.String(length=500), nullable=False),
		sa.Column('description', sa.Text(), nullable=True),
		sa.Column('created_at', sa.DateTime(), nullable=False),
		sa.Column('updated_at', sa.DateTime(), nullable=True),
	)

	op.create_table(
		'playbooks',
		sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
		sa.Column('name', sa.String(length=200), nullable=False, unique=True),
		sa.Column('steps', postgresql.JSONB(), nullable=True),
		sa.Column('created_at', sa.DateTime(), nullable=False),
	)

	op.create_table(
		'scans',
		sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
		sa.Column('target_id', postgresql.UUID(as_uuid=True), nullable=False),
		sa.Column('playbook_id', postgresql.UUID(as_uuid=True), nullable=True),
		sa.Column('tools', postgresql.ARRAY(sa.String()), nullable=False),
		sa.Column('status', sa.Enum('pending', 'running', 'completed', 'failed', name='scanstatus'), nullable=False),
		sa.Column('started_at', sa.DateTime(), nullable=True),
		sa.Column('finished_at', sa.DateTime(), nullable=True),
		sa.Column('created_at', sa.DateTime(), nullable=False),
		sa.Column('error_message', sa.Text(), nullable=True),
		sa.Column('scan_metadata', postgresql.JSONB(), nullable=True),
		sa.ForeignKeyConstraint(['target_id'], ['targets.id'], ondelete='CASCADE'),
		sa.ForeignKeyConstraint(['playbook_id'], ['playbooks.id'], ondelete='SET NULL'),
	)

	op.create_table(
		'findings',
		sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
		sa.Column('scan_id', postgresql.UUID(as_uuid=True), nullable=False),
		sa.Column('tool', sa.String(length=50), nullable=False),
		sa.Column('title', sa.String(length=500), nullable=False),
		sa.Column('severity', sa.Enum('critical', 'high', 'medium', 'low', 'info', name='severity'), nullable=False),
		sa.Column('cvss_score', sa.Float(), nullable=True),
		sa.Column('cve_id', sa.String(length=50), nullable=True),
		sa.Column('owasp_category', sa.String(length=100), nullable=True),
		sa.Column('endpoint', sa.String(length=1000), nullable=True),
		sa.Column('description', sa.Text(), nullable=True),
		sa.Column('recommendation', sa.Text(), nullable=True),
		sa.Column('ai_summary', sa.Text(), nullable=True),
		sa.Column('ai_recommendation', sa.Text(), nullable=True),
		sa.Column('probable_fp', sa.Boolean(), nullable=False, server_default=sa.text('false')),
		sa.Column('raw_output', postgresql.JSONB(), nullable=True),
		sa.Column('created_at', sa.DateTime(), nullable=False),
		sa.ForeignKeyConstraint(['scan_id'], ['scans.id'], ondelete='CASCADE'),
	)

	op.create_table(
		'artifacts',
		sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
		sa.Column('scan_id', postgresql.UUID(as_uuid=True), nullable=False),
		sa.Column('tool', sa.String(length=50), nullable=False),
		sa.Column('path', sa.String(length=1000), nullable=False),
		sa.Column('format', sa.String(length=50), nullable=True),
		sa.Column('created_at', sa.DateTime(), nullable=False),
		sa.ForeignKeyConstraint(['scan_id'], ['scans.id'], ondelete='CASCADE'),
	)


def downgrade() -> None:
	op.drop_table('artifacts')
	op.drop_table('findings')
	op.drop_table('scans')
	op.drop_table('playbooks')
	op.drop_table('targets')
