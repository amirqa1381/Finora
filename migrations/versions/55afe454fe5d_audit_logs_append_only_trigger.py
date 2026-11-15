"""audit_logs append-only trigger

Revision ID: 55afe454fe5d
Revises: 2962d18dbd77
"""
from alembic import op
import sqlalchemy as sa


revision = '55afe454fe5d'
down_revision = '2962d18dbd77'


def upgrade() -> None:
    op.execute(
        """
        CREATE FUNCTION audit_logs_block_modification() RETURNS trigger AS $$
        BEGIN
            RAISE EXCEPTION 'audit_logs is append-only';
        END;
        $$ LANGUAGE plpgsql;
        """
    )
    op.execute(
        """
        CREATE TRIGGER audit_logs_no_update_delete
        BEFORE UPDATE OR DELETE ON audit_logs
        FOR EACH ROW EXECUTE FUNCTION audit_logs_block_modification();
        """
    )
    op.execute(
        """
        CREATE TRIGGER audit_logs_no_truncate
        BEFORE TRUNCATE ON audit_logs
        FOR EACH STATEMENT EXECUTE FUNCTION audit_logs_block_modification();
        """
    )


def downgrade() -> None:
    op.execute("DROP TRIGGER IF EXISTS audit_logs_no_truncate ON audit_logs")
    op.execute("DROP TRIGGER IF EXISTS audit_logs_no_update_delete ON audit_logs")
    op.execute("DROP FUNCTION IF EXISTS audit_logs_block_modification()")