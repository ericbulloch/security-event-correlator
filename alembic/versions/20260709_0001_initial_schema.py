"""initial schema

Single migration that creates the full database schema.

Revision ID: 0001
Revises:
Create Date: 2026-07-09

"""
from typing import Sequence, Union

from alembic import op

revision: str = "0001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ── events ────────────────────────────────────────────────────────────────
    op.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id              SERIAL PRIMARY KEY,
            timestamp       TIMESTAMP NOT NULL,
            source          VARCHAR(256) NOT NULL,
            event_type      VARCHAR(256) NOT NULL,
            severity        VARCHAR(50) NOT NULL,
            "user"          VARCHAR(256),
            action          VARCHAR(256) NOT NULL,
            resource        VARCHAR(1024),
            details         JSONB NOT NULL,
            raw_log         TEXT,
            processed       INTEGER DEFAULT 0,
            processed_at    TIMESTAMP,
            correlation_id  UUID,
            created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    op.execute("CREATE INDEX IF NOT EXISTS idx_events_timestamp      ON events(timestamp)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_events_source         ON events(source)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_events_severity       ON events(severity)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_events_processed      ON events(processed)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_events_correlation_id ON events(correlation_id)")
    op.execute('CREATE INDEX IF NOT EXISTS idx_events_user           ON events("user")')
    # Expression index for cross-source IP correlation (IPSweepRule).
    op.execute("CREATE INDEX IF NOT EXISTS idx_events_ip ON events ((details->>'ip'))")

    # ── alerts ────────────────────────────────────────────────────────────────
    op.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id                  SERIAL PRIMARY KEY,
            timestamp           TIMESTAMP NOT NULL,
            type                VARCHAR(256) NOT NULL,
            severity            VARCHAR(50) NOT NULL,
            description         TEXT NOT NULL,
            evidence            JSONB NOT NULL,
            ai_reasoning        TEXT NOT NULL,
            confidence          FLOAT NOT NULL,
            recommended_actions JSONB NOT NULL,
            fingerprint         VARCHAR(64),
            status              VARCHAR(20) NOT NULL DEFAULT 'open',
            hit_count           INTEGER NOT NULL DEFAULT 1,
            last_seen_at        TIMESTAMP,
            created_at          TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    op.execute("CREATE INDEX IF NOT EXISTS idx_alerts_type      ON alerts(type)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_alerts_severity  ON alerts(severity)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_alerts_status    ON alerts(status)")
    # Partial index: fast fingerprint lookup for open-alert deduplication upserts.
    op.execute("""
        CREATE INDEX IF NOT EXISTS idx_alerts_fingerprint_open
        ON alerts(fingerprint)
        WHERE status = 'open'
    """)

    # ── rate_limits ───────────────────────────────────────────────────────────
    op.execute("""
        CREATE TABLE IF NOT EXISTS rate_limits (
            id             SERIAL PRIMARY KEY,
            client_name    VARCHAR(256) NOT NULL,
            request_count  INTEGER DEFAULT 0,
            window_start   TIMESTAMP NOT NULL,
            UNIQUE(client_name, window_start)
        )
    """)
    op.execute("CREATE INDEX IF NOT EXISTS idx_rate_limits_client_window ON rate_limits(client_name, window_start)")

    # ── api_keys ──────────────────────────────────────────────────────────────
    op.execute("""
        CREATE TABLE IF NOT EXISTS api_keys (
            id           SERIAL PRIMARY KEY,
            key_hash     VARCHAR(64) NOT NULL UNIQUE,
            client_name  VARCHAR(256) NOT NULL,
            is_active    BOOLEAN NOT NULL DEFAULT TRUE,
            created_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_used_at TIMESTAMP,
            expires_at   TIMESTAMP,
            rate_limit   INTEGER NOT NULL DEFAULT 100
        )
    """)
    op.execute("CREATE INDEX IF NOT EXISTS idx_api_keys_hash   ON api_keys(key_hash)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_api_keys_client ON api_keys(client_name)")

    # ── users ─────────────────────────────────────────────────────────────────
    op.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id            SERIAL PRIMARY KEY,
            username      VARCHAR(256) NOT NULL UNIQUE,
            email         VARCHAR(256),
            password_hash VARCHAR(256) NOT NULL,
            is_admin      BOOLEAN NOT NULL DEFAULT FALSE,
            is_active     BOOLEAN NOT NULL DEFAULT TRUE,
            created_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    op.execute("CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)")


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS users")
    op.execute("DROP TABLE IF EXISTS api_keys")
    op.execute("DROP TABLE IF EXISTS rate_limits")
    op.execute("DROP TABLE IF EXISTS alerts")
    op.execute("DROP TABLE IF EXISTS events")
