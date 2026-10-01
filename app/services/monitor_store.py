import hashlib
import os
import secrets
import uuid
from threading import Lock
from datetime import datetime, timezone, timedelta

import httpx
import psycopg
from app.services.db import connect_kwargs, database_url

from app.services.url_safety import read_response_bytes, safe_async_client, validate_public_url

_INIT_LOCK = Lock()
_SCHEMA_READY = False

MAX_WEBHOOK_RESPONSE_BYTES = 64 * 1024

SCHEMA = """
CREATE TABLE IF NOT EXISTS monitors (
    id TEXT PRIMARY KEY,
    owner_key_hash TEXT NOT NULL,
    url TEXT NOT NULL,
    interval_minutes INTEGER NOT NULL,
    webhook_url TEXT NOT NULL,
    last_price DOUBLE PRECISION,
    last_checked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_monitors_owner_created ON monitors (owner_key_hash, created_at DESC);

CREATE TABLE IF NOT EXISTS price_history (
    id BIGSERIAL PRIMARY KEY,
    monitor_id TEXT NOT NULL REFERENCES monitors(id) ON DELETE CASCADE,
    price DOUBLE PRECISION,
    currency TEXT,
    captured_at TIMESTAMPTZ NOT NULL,
    source_url TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_price_history_monitor_captured
    ON price_history (monitor_id, captured_at DESC);

CREATE TABLE IF NOT EXISTS api_accounts (
    api_key_hash TEXT PRIMARY KEY,
    plan TEXT NOT NULL DEFAULT 'free',
    credits_balance INTEGER NOT NULL DEFAULT 100,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    customer_user_id TEXT
);
CREATE TABLE IF NOT EXISTS api_keys (
    api_key_hash TEXT PRIMARY KEY,
    key_prefix TEXT NOT NULL,
    account_key_hash TEXT NOT NULL REFERENCES api_accounts(api_key_hash) ON DELETE CASCADE,
    active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL,
    last_used_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_api_keys_account ON api_keys (account_key_hash, created_at DESC);
CREATE TABLE IF NOT EXISTS api_usage (
    id BIGSERIAL PRIMARY KEY,
    api_key_hash TEXT NOT NULL,
    endpoint TEXT NOT NULL,
    credits INTEGER NOT NULL,
    created_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_api_usage_key_created ON api_usage (api_key_hash, created_at DESC);

CREATE TABLE IF NOT EXISTS monitor_run_leases (
    monitor_id TEXT PRIMARY KEY REFERENCES monitors(id) ON DELETE CASCADE,
    lease_token TEXT NOT NULL,
    locked_until TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS webhook_deliveries (
    event_id TEXT PRIMARY KEY,
    monitor_id TEXT NOT NULL REFERENCES monitors(id) ON DELETE CASCADE,
    payload TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    attempts INTEGER NOT NULL DEFAULT 0,
    next_attempt_at TIMESTAMPTZ NOT NULL,
    locked_until TIMESTAMPTZ,
    lease_token TEXT,
    last_error TEXT,
    created_at TIMESTAMPTZ NOT NULL,
    delivered_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_pending
    ON webhook_deliveries (next_attempt_at, status)
    WHERE status = 'pending';

CREATE TABLE IF NOT EXISTS api_rate_limits (
    api_key_hash TEXT PRIMARY KEY,
    window_start TIMESTAMPTZ NOT NULL,
    request_count INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS research_runs (
    id TEXT PRIMARY KEY,
    owner_key_hash TEXT NOT NULL,
    url TEXT NOT NULL,
    source_type TEXT,
    market TEXT,
    locale TEXT,
    title TEXT,
    comments_count INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_research_runs_owner_created ON research_runs (owner_key_hash, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_research_runs_url_created ON research_runs (url, created_at DESC);

CREATE TABLE IF NOT EXISTS research_comments (
    id BIGSERIAL PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES research_runs(id) ON DELETE CASCADE,
    body TEXT NOT NULL,
    body_hash TEXT NOT NULL,
    locale TEXT,
    captured_at TIMESTAMPTZ NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_research_comments_run_hash ON research_comments (run_id, body_hash);
CREATE INDEX IF NOT EXISTS idx_research_comments_hash ON research_comments (body_hash);

CREATE TABLE IF NOT EXISTS research_pain_points (
    id BIGSERIAL PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES research_runs(id) ON DELETE CASCADE,
    pain TEXT NOT NULL,
    count INTEGER NOT NULL,
    share_percent DOUBLE PRECISION NOT NULL,
    created_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_research_pains_run_count ON research_pain_points (run_id, count DESC);
"""

def _db_url() -> str:
    return database_url()

def _account_hash(api_key: str) -> str:
    return hashlib.sha256(api_key.encode()).hexdigest()

def _init(conn):
    global _SCHEMA_READY
    if _SCHEMA_READY:
        return
    with _INIT_LOCK:
        if _SCHEMA_READY:
            return
        conn.execute(SCHEMA)
        # Safe migration for the existing monitor table.
        conn.execute("ALTER TABLE monitors ADD COLUMN IF NOT EXISTS owner_key_hash TEXT")
        conn.execute("ALTER TABLE api_accounts ADD COLUMN IF NOT EXISTS customer_user_id TEXT")
        conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_api_accounts_customer_user ON api_accounts (customer_user_id) WHERE customer_user_id IS NOT NULL")
        master_key = os.getenv("EC_PULSE_API_KEY")
        if master_key:
            key_hash = _account_hash(master_key)
            now = datetime.now(timezone.utc)
            conn.execute("""INSERT INTO api_accounts (api_key_hash, plan, credits_balance, created_at, updated_at)
                VALUES (%s, 'free', 100, %s, %s) ON CONFLICT (api_key_hash) DO NOTHING""", (key_hash, now, now))
            conn.execute("""INSERT INTO api_keys (api_key_hash, key_prefix, account_key_hash, active, created_at)
                VALUES (%s, %s, %s, TRUE, %s) ON CONFLICT (api_key_hash) DO NOTHING""", (key_hash, master_key[:12], key_hash, now))
            conn.execute("UPDATE monitors SET owner_key_hash = %s WHERE owner_key_hash IS NULL", (key_hash,))
        conn.commit()
        _SCHEMA_READY = True

def validate_api_key(api_key: str) -> bool:
    key_hash = _account_hash(api_key)
    with psycopg.connect(_db_url(), **connect_kwargs()) as conn:
        _init(conn)
        row = conn.execute("SELECT active FROM api_keys WHERE api_key_hash = %s", (key_hash,)).fetchone()
        if not row or not row[0]: return False
        now = datetime.now(timezone.utc)
        conn.execute("UPDATE api_keys SET last_used_at = %s WHERE api_key_hash = %s", (now, key_hash))
        conn.commit()
    return True

def ensure_api_account(api_key: str) -> dict:
    key_hash = _account_hash(api_key)
    with psycopg.connect(_db_url(), **connect_kwargs()) as conn:
        _init(conn)
        row = conn.execute(
            """SELECT a.plan, a.credits_balance, a.created_at, a.updated_at
            FROM api_keys k
            JOIN api_accounts a ON a.api_key_hash = k.account_key_hash
            WHERE k.api_key_hash = %s AND k.active = TRUE""",
            (key_hash,),
        ).fetchone()
        if not row: raise RuntimeError("API key is not provisioned")
    return {"plan": row[0], "credits_balance": row[1], "created_at": row[2].isoformat(), "updated_at": row[3].isoformat()}

def create_api_key(plan: str = "free", credits: int = 100) -> dict:
    if plan not in {"free", "pro", "business"}: raise ValueError("plan must be free, pro, or business")
    if credits < 0: raise ValueError("credits must be non-negative")
    raw_key = f"ecp_live_{secrets.token_urlsafe(32)}"
    key_hash = _account_hash(raw_key); now = datetime.now(timezone.utc)
    with psycopg.connect(_db_url(), **connect_kwargs()) as conn:
        _init(conn)
        conn.execute("INSERT INTO api_accounts (api_key_hash, plan, credits_balance, created_at, updated_at) VALUES (%s, %s, %s, %s, %s)", (key_hash, plan, credits, now, now))
        conn.execute("INSERT INTO api_keys (api_key_hash, key_prefix, account_key_hash, active, created_at) VALUES (%s, %s, %s, TRUE, %s)", (key_hash, raw_key[:12], key_hash, now))
        conn.commit()
    return {"api_key": raw_key, "key_prefix": raw_key[:12], "plan": plan, "credits_balance": credits, "created_at": now.isoformat(), "warning": "Store this API key securely. It will not be shown again."}

def provision_customer_api_key(user_id: str, rotate: bool = False) -> dict:
    """Provision or rotate an API key for an authenticated customer account."""
    user_id = user_id.strip()
    if not user_id or len(user_id) > 255:
        raise ValueError("Invalid customer user id")
    raw_key = f"ecp_live_{secrets.token_urlsafe(32)}"
    key_hash = _account_hash(raw_key)
    now = datetime.now(timezone.utc)
    with psycopg.connect(_db_url(), **connect_kwargs()) as conn:
        _init(conn)
        # Serialize provisioning/rotation for the same authenticated customer.
        # This closes the first-login race where two requests could both observe
        # no account before the unique customer_user_id index is enforced.
        conn.execute("SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))", (user_id,))
        row = conn.execute(
            "SELECT api_key_hash, plan, credits_balance FROM api_accounts WHERE customer_user_id = %s FOR UPDATE",
            (user_id,),
        ).fetchone()
        if row:
            account_hash, plan, balance = row
            if not rotate:
                existing = conn.execute(
                    "SELECT key_prefix FROM api_keys WHERE account_key_hash = %s AND active = TRUE ORDER BY created_at DESC LIMIT 1",
                    (account_hash,),
                ).fetchone()
                if existing:
                    return {"created": False, "key_prefix": existing[0], "plan": plan, "credits_balance": balance, "warning": "The existing API key is not returned again. Rotate to issue a new key."}
            conn.execute("UPDATE api_keys SET active = FALSE WHERE account_key_hash = %s AND active = TRUE", (account_hash,))
        else:
            account_hash = key_hash
            plan = "free"
            balance = 100
            conn.execute(
                "INSERT INTO api_accounts (api_key_hash, plan, credits_balance, created_at, updated_at, customer_user_id) VALUES (%s, 'free', 100, %s, %s, %s)",
                (account_hash, now, now, user_id),
            )
        conn.execute(
            "INSERT INTO api_keys (api_key_hash, key_prefix, account_key_hash, active, created_at) VALUES (%s, %s, %s, TRUE, %s)",
            (key_hash, raw_key[:12], account_hash, now),
        )
        conn.commit()
    return {"created": True, "api_key": raw_key, "key_prefix": raw_key[:12], "plan": plan, "credits_balance": balance, "warning": "Store this API key securely. It will not be shown again."}

def list_customer_api_keys(user_id: str) -> list[dict]:
    user_id = user_id.strip()
    if not user_id or len(user_id) > 255:
        raise ValueError("Invalid customer user id")
    with psycopg.connect(_db_url(), **connect_kwargs()) as conn:
        _init(conn)
        rows = conn.execute(
            """SELECT k.key_prefix, k.active, k.created_at, k.last_used_at,
                      a.plan, a.credits_balance
               FROM api_keys k
               JOIN api_accounts a ON a.api_key_hash = k.account_key_hash
               WHERE a.customer_user_id = %s
               ORDER BY k.created_at DESC""",
            (user_id,),
        ).fetchall()
    return [
        {
            "key_prefix": row[0],
            "active": row[1],
            "created_at": row[2].isoformat(),
            "last_used_at": row[3].isoformat() if row[3] else None,
            "plan": row[4],
            "credits_balance": row[5],
        }
        for row in rows
    ]


def revoke_customer_api_key(user_id: str, key_prefix: str) -> bool:
    user_id = user_id.strip()
    key_prefix = key_prefix.strip()
    if not user_id or len(user_id) > 255:
        raise ValueError("Invalid customer user id")
    if not key_prefix or len(key_prefix) > 32:
        raise ValueError("Invalid API key prefix")
    with psycopg.connect(_db_url(), **connect_kwargs()) as conn:
        _init(conn)
        cur = conn.execute(
            """UPDATE api_keys k
               SET active = FALSE
               FROM api_accounts a
               WHERE k.account_key_hash = a.api_key_hash
                 AND a.customer_user_id = %s
                 AND k.key_prefix = %s
                 AND k.active = TRUE""",
            (user_id, key_prefix),
        )
        conn.commit()
        return cur.rowcount > 0


def list_api_keys() -> list[dict]:
    with psycopg.connect(_db_url(), **connect_kwargs()) as conn:
        _init(conn)
        rows = conn.execute("""SELECT k.key_prefix, k.active, k.created_at, k.last_used_at, a.plan, a.credits_balance
            FROM api_keys k JOIN api_accounts a ON a.api_key_hash = k.account_key_hash ORDER BY k.created_at DESC""").fetchall()
    return [{"key_prefix": r[0], "active": r[1], "created_at": r[2].isoformat(), "last_used_at": r[3].isoformat() if r[3] else None, "plan": r[4], "credits_balance": r[5]} for r in rows]

def revoke_api_key(api_key: str) -> bool:
    key_hash = _account_hash(api_key)
    with psycopg.connect(_db_url(), **connect_kwargs()) as conn:
        _init(conn); cur = conn.execute("UPDATE api_keys SET active = FALSE WHERE api_key_hash = %s", (key_hash,)); conn.commit(); return cur.rowcount > 0

def consume_credit(api_key: str, endpoint: str, credits: int = 1) -> dict:
    if credits < 1: raise ValueError("credits must be positive")
    key_hash = _account_hash(api_key); now = datetime.now(timezone.utc)
    with psycopg.connect(_db_url(), **connect_kwargs()) as conn:
        _init(conn)
        row = conn.execute("""SELECT a.api_key_hash, a.credits_balance FROM api_accounts a JOIN api_keys k ON k.account_key_hash = a.api_key_hash
            WHERE k.api_key_hash = %s AND k.active = TRUE FOR UPDATE OF k, a""", (key_hash,)).fetchone()
        if not row: raise RuntimeError("Invalid or revoked API key")
        account_hash, balance = row
        if balance < credits: raise RuntimeError("Insufficient API credits")
        remaining = balance - credits
        conn.execute("UPDATE api_accounts SET credits_balance = %s, updated_at = %s WHERE api_key_hash = %s", (remaining, now, account_hash))
        conn.execute("UPDATE api_keys SET last_used_at = %s WHERE api_key_hash = %s", (now, key_hash))
        conn.execute("INSERT INTO api_usage (api_key_hash, endpoint, credits, created_at) VALUES (%s, %s, %s, %s)", (key_hash, endpoint, credits, now)); conn.commit()
    return {"credits_used": credits, "credits_remaining": remaining}

def get_account_usage(api_key: str) -> dict:
    key_hash = _account_hash(api_key)
    with psycopg.connect(_db_url(), **connect_kwargs()) as conn:
        _init(conn)
        account = conn.execute(
            """SELECT a.plan, a.credits_balance, a.created_at, a.updated_at
               FROM api_accounts a
               JOIN api_keys k ON k.account_key_hash = a.api_key_hash
               WHERE k.api_key_hash = %s AND k.active = TRUE""",
            (key_hash,),
        ).fetchone()
        if not account:
            raise RuntimeError("API key is not provisioned")
        account_lookup = """(
            SELECT account_key_hash FROM api_keys
            WHERE api_key_hash = %s AND active = TRUE
        )"""
        rows = conn.execute(
            f"""SELECT u.endpoint, SUM(u.credits), COUNT(*)
                FROM api_usage u
                JOIN api_keys k ON k.api_key_hash = u.api_key_hash
                WHERE k.account_key_hash = {account_lookup}
                GROUP BY u.endpoint ORDER BY SUM(u.credits) DESC""",
            (key_hash,),
        ).fetchall()
        monthly = conn.execute(
            f"""SELECT COALESCE(SUM(u.credits), 0), COUNT(*)
                FROM api_usage u
                JOIN api_keys k ON k.api_key_hash = u.api_key_hash
                WHERE k.account_key_hash = {account_lookup}
                  AND u.created_at >= date_trunc('month', CURRENT_TIMESTAMP)""",
            (key_hash,),
        ).fetchone()
        recent = conn.execute(
            f"""SELECT COALESCE(SUM(u.credits), 0), COUNT(*)
                FROM api_usage u
                JOIN api_keys k ON k.api_key_hash = u.api_key_hash
                WHERE k.account_key_hash = {account_lookup}
                  AND u.created_at >= CURRENT_TIMESTAMP - INTERVAL '24 hours'""",
            (key_hash,),
        ).fetchone()
    return {
        "plan": account[0],
        "credits_balance": account[1],
        "total_credits_used": sum(r[1] for r in rows),
        "created_at": account[2].isoformat(),
        "updated_at": account[3].isoformat(),
        "usage": [{"endpoint": r[0], "credits": r[1], "requests": r[2]} for r in rows],
        "period_usage": {
            "month_to_date": {"credits": monthly[0], "requests": monthly[1]},
            "last_24_hours": {"credits": recent[0], "requests": recent[1]},
        },
    }

def get_customer_usage(user_id: str, days: int = 30) -> dict:
    user_id = user_id.strip()
    days = max(1, min(days, 365))
    if not user_id or len(user_id) > 255:
        raise ValueError("Invalid customer user id")
    with psycopg.connect(_db_url(), **connect_kwargs()) as conn:
        _init(conn)
        account = conn.execute(
            """SELECT plan, credits_balance, created_at, updated_at
               FROM api_accounts WHERE customer_user_id = %s""",
            (user_id,),
        ).fetchone()
        if not account:
            raise RuntimeError("Customer account is not provisioned")
        rows = conn.execute(
            """SELECT u.endpoint,
                      COALESCE(SUM(u.credits), 0) AS credits,
                      COUNT(*) AS requests,
                      COUNT(*) FILTER (WHERE u.credits > 0) AS billable_requests
               FROM api_usage u
               JOIN api_keys k ON k.api_key_hash = u.api_key_hash
               JOIN api_accounts a ON a.api_key_hash = k.account_key_hash
               WHERE a.customer_user_id = %s
                 AND u.created_at >= CURRENT_TIMESTAMP - (%s * INTERVAL '1 day')
               GROUP BY u.endpoint
               ORDER BY credits DESC, requests DESC""",
            (user_id, days),
        ).fetchall()
        daily = conn.execute(
            """SELECT DATE(u.created_at) AS day,
                      COALESCE(SUM(u.credits), 0),
                      COUNT(*)
               FROM api_usage u
               JOIN api_keys k ON k.api_key_hash = u.api_key_hash
               JOIN api_accounts a ON a.api_key_hash = k.account_key_hash
               WHERE a.customer_user_id = %s
                 AND u.created_at >= CURRENT_TIMESTAMP - (%s * INTERVAL '1 day')
               GROUP BY DATE(u.created_at)
               ORDER BY day DESC""",
            (user_id, days),
        ).fetchall()
        key_rows = conn.execute(
            """SELECT k.key_prefix, k.active, COALESCE(SUM(u.credits), 0), COUNT(u.id)
               FROM api_keys k
               JOIN api_accounts a ON a.api_key_hash = k.account_key_hash
               LEFT JOIN api_usage u ON u.api_key_hash = k.api_key_hash
                 AND u.created_at >= CURRENT_TIMESTAMP - (%s * INTERVAL '1 day')
               WHERE a.customer_user_id = %s
               GROUP BY k.key_prefix, k.active, k.created_at
               ORDER BY k.created_at DESC""",
            (days, user_id),
        ).fetchall()
    total_credits = sum(int(row[1]) for row in rows)
    total_requests = sum(int(row[2]) for row in rows)
    return {
        "plan": account[0],
        "credits_balance": account[1],
        "window_days": days,
        "window_start": (datetime.now(timezone.utc) - timedelta(days=days)).isoformat(),
        "total_credits_used": total_credits,
        "total_requests": total_requests,
        "by_endpoint": [
            {"endpoint": row[0], "credits": int(row[1]), "requests": int(row[2]), "billable_requests": int(row[3])}
            for row in rows
        ],
        "daily": [
            {"date": row[0].isoformat(), "credits": int(row[1]), "requests": int(row[2])}
            for row in daily
        ],
        "by_key": [
            {"key_prefix": row[0], "active": row[1], "credits": int(row[2]), "requests": int(row[3])}
            for row in key_rows
        ],
        "account": {
            "created_at": account[2].isoformat(),
            "updated_at": account[3].isoformat(),
        },
    }


def get_customer_usage_alert(user_id: str) -> dict:
    user_id = user_id.strip()
    if not user_id or len(user_id) > 255:
        raise ValueError("Invalid customer user id")
    with psycopg.connect(_db_url(), **connect_kwargs()) as conn:
        _init(conn)
        row = conn.execute(
            """SELECT plan, credits_balance
               FROM api_accounts WHERE customer_user_id = %s""",
            (user_id,),
        ).fetchone()
        if not row:
            raise RuntimeError("Customer account is not provisioned")
        used = conn.execute(
            """SELECT COALESCE(SUM(u.credits), 0)
               FROM api_usage u
               JOIN api_keys k ON k.api_key_hash = u.api_key_hash
               JOIN api_accounts a ON a.api_key_hash = k.account_key_hash
               WHERE a.customer_user_id = %s
                 AND u.created_at >= date_trunc('month', CURRENT_TIMESTAMP)""",
            (user_id,),
        ).fetchone()[0]
    quota_env = {
        "free": "EC_PULSE_FREE_MONTHLY_CREDITS",
        "pro": "EC_PULSE_PRO_MONTHLY_CREDITS",
        "business": "EC_PULSE_BUSINESS_MONTHLY_CREDITS",
    }[row[0]]
    raw_quota = os.getenv(quota_env, "").strip()
    quota = int(raw_quota) if raw_quota.isdigit() and int(raw_quota) > 0 else None
    if quota is None:
        return {
            "configured": False,
            "plan": row[0],
            "credits_used_this_month": int(used),
            "credits_remaining": row[1],
            "thresholds": [{"percent": 85, "triggered": False}, {"percent": 100, "triggered": False}],
            "message": "Monthly credit quota is not configured for this plan.",
        }
    percent = round((int(used) / quota) * 100, 2)
    return {
        "configured": True,
        "plan": row[0],
        "monthly_quota": quota,
        "credits_used_this_month": int(used),
        "credits_remaining": row[1],
        "usage_percent": percent,
        "thresholds": [
            {"percent": 85, "triggered": percent >= 85},
            {"percent": 100, "triggered": percent >= 100},
        ],
    }


def create_monitor(api_key: str, url: str, interval_minutes: int, webhook_url: str) -> dict:
    now = datetime.now(timezone.utc); monitor_id = str(uuid.uuid4()); owner = _account_hash(api_key)
    with psycopg.connect(_db_url(), **connect_kwargs()) as conn:
        _init(conn)
        conn.execute("INSERT INTO monitors (id, owner_key_hash, url, interval_minutes, webhook_url, created_at) VALUES (%s, %s, %s, %s, %s, %s)", (monitor_id, owner, url, interval_minutes, webhook_url, now)); conn.commit()
    return {"id": monitor_id, "url": url, "interval_minutes": interval_minutes, "webhook_url": webhook_url, "status": "active", "created_at": now.isoformat()}

def create_monitor_with_credit(api_key: str, url: str, interval_minutes: int, webhook_url: str, endpoint: str) -> tuple[dict, dict]:
    """Create a monitor and consume its creation credit in one DB transaction."""
    now = datetime.now(timezone.utc)
    monitor_id = str(uuid.uuid4())
    key_hash = _account_hash(api_key)
    with psycopg.connect(_db_url(), **connect_kwargs()) as conn:
        _init(conn)
        row = conn.execute(
            """SELECT a.api_key_hash, a.credits_balance
               FROM api_accounts a
               JOIN api_keys k ON k.account_key_hash = a.api_key_hash
               WHERE k.api_key_hash = %s AND k.active = TRUE
               FOR UPDATE OF k, a""",
            (key_hash,),
        ).fetchone()
        if not row:
            raise RuntimeError("Invalid or revoked API key")
        account_hash, balance = row
        if balance < 1:
            raise RuntimeError("Insufficient API credits")
        remaining = balance - 1
        conn.execute(
            "UPDATE api_accounts SET credits_balance = %s, updated_at = %s WHERE api_key_hash = %s",
            (remaining, now, account_hash),
        )
        conn.execute(
            "UPDATE api_keys SET last_used_at = %s WHERE api_key_hash = %s",
            (now, key_hash),
        )
        conn.execute(
            "INSERT INTO api_usage (api_key_hash, endpoint, credits, created_at) VALUES (%s, %s, %s, %s)",
            (key_hash, endpoint, 1, now),
        )
        conn.execute(
            "INSERT INTO monitors (id, owner_key_hash, url, interval_minutes, webhook_url, created_at) VALUES (%s, %s, %s, %s, %s, %s)",
            (monitor_id, account_hash, url, interval_minutes, webhook_url, now),
        )
        conn.commit()
    return (
        {"id": monitor_id, "url": url, "interval_minutes": interval_minutes, "webhook_url": webhook_url, "status": "active", "created_at": now.isoformat()},
        {"credits_used": 1, "credits_remaining": remaining},
    )

def list_monitors(api_key: str) -> list[dict]:
    key_hash = _account_hash(api_key)
    with psycopg.connect(_db_url(), **connect_kwargs()) as conn:
        _init(conn)
        rows = conn.execute(
            """SELECT m.id, m.url, m.interval_minutes, m.webhook_url, m.last_price, m.last_checked_at, m.created_at
               FROM monitors m
               JOIN api_keys k ON k.account_key_hash = m.owner_key_hash
               WHERE k.api_key_hash = %s AND k.active = TRUE
               ORDER BY m.created_at DESC""",
            (key_hash,),
        ).fetchall()
    return [{"id": r[0], "url": r[1], "interval_minutes": r[2], "webhook_url": r[3], "last_price": r[4], "last_checked_at": r[5].isoformat() if r[5] else None, "created_at": r[6].isoformat()} for r in rows]

def _owned_monitor(conn, api_key: str, monitor_id: str):
    row = conn.execute(
        """SELECT m.id, m.url, m.last_price, m.last_checked_at
           FROM monitors m
           JOIN api_keys k ON k.account_key_hash = m.owner_key_hash
           WHERE m.id = %s AND k.api_key_hash = %s AND k.active = TRUE""",
        (monitor_id, _account_hash(api_key)),
    ).fetchone()
    if not row:
        raise KeyError(monitor_id)
    return row

def _history_rows(conn, monitor_id: str, limit: int):
    return conn.execute("SELECT price, currency, captured_at, source_url FROM price_history WHERE monitor_id = %s ORDER BY captured_at DESC, id DESC LIMIT %s", (monitor_id, limit)).fetchall()

def get_price_history(api_key: str, monitor_id: str, limit: int = 100) -> dict:
    with psycopg.connect(_db_url(), **connect_kwargs()) as conn:
        _init(conn); monitor = _owned_monitor(conn, api_key, monitor_id); rows = _history_rows(conn, monitor_id, limit)
    points = [{"price": r[0], "currency": r[1], "captured_at": r[2].isoformat(), "source_url": r[3]} for r in rows]
    numeric = [p["price"] for p in points if p["price"] is not None]; current = numeric[0] if numeric else monitor[2]; lowest = min(numeric) if numeric else None; highest = max(numeric) if numeric else None; first = numeric[-1] if numeric else None
    change_percent = round(((current - first) / first) * 100, 2) if first not in (None, 0) and current is not None else None
    return {"monitor": {"id": monitor[0], "url": monitor[1], "last_price": monitor[2], "last_checked_at": monitor[3].isoformat() if monitor[3] else None}, "summary": {"points": len(points), "current_price": current, "lowest_price": lowest, "highest_price": highest, "change_percent": change_percent}, "history": points}

def get_price_opportunity(api_key: str, monitor_id: str, limit: int = 100) -> dict:
    with psycopg.connect(_db_url(), **connect_kwargs()) as conn:
        _init(conn); monitor = _owned_monitor(conn, api_key, monitor_id); rows = _history_rows(conn, monitor_id, limit)
    prices = [r[0] for r in rows if r[0] is not None]; current = prices[0] if prices else monitor[2]; lowest = min(prices) if prices else None; highest = max(prices) if prices else None; baseline = sum(prices) / len(prices) if prices else None
    discount_vs_high = round(((highest-current)/highest)*100, 2) if highest and current is not None else None; discount_vs_average = round(((baseline-current)/baseline)*100, 2) if baseline and current is not None else None
    signal = "historical_low" if current is not None and lowest is not None and current <= lowest else "below_average" if discount_vs_average and discount_vs_average > 10 else "normal"
    return {"monitor_id": monitor_id, "url": monitor[1], "current_price": current, "currency": rows[0][1] if rows else None, "metrics": {"historical_low": lowest, "historical_high": highest, "average_price": round(baseline, 2) if baseline is not None else None, "discount_vs_high_percent": discount_vs_high, "discount_vs_average_percent": discount_vs_average}, "signal": signal, "captured_at": monitor[3].isoformat() if monitor[3] else None}

def _normalize_research_text(text: str) -> str:
    return " ".join(text.lower().split())


def save_research_run(api_key: str, item: dict, analysis: dict) -> dict:
    run_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc)
    comments = [x.strip() for x in item.get("comments", []) if isinstance(x, str) and x.strip()]
    owner = _account_hash(api_key)
    with psycopg.connect(_db_url(), **connect_kwargs()) as conn:
        _init(conn)
        conn.execute(
            """INSERT INTO research_runs
            (id, owner_key_hash, url, source_type, market, locale, title, comments_count, created_at)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
            (run_id, owner, item.get("url"), item.get("source_type"), item.get("market"),
             item.get("locale"), item.get("title"), len(comments), now),
        )
        for body in comments:
            body_hash = hashlib.sha256(_normalize_research_text(body).encode()).hexdigest()
            conn.execute(
                """INSERT INTO research_comments (run_id, body, body_hash, locale, captured_at)
                VALUES (%s,%s,%s,%s,%s) ON CONFLICT (run_id, body_hash) DO NOTHING""",
                (run_id, body, body_hash, item.get("locale"), now),
            )
        for pain in analysis.get("pain_points", []):
            conn.execute(
                """INSERT INTO research_pain_points
                (run_id, pain, count, share_percent, created_at)
                VALUES (%s,%s,%s,%s,%s)""",
                (run_id, pain.get("pain", "unknown"), int(pain.get("count", 0)),
                 float(pain.get("share_percent", 0)), now),
            )
        previous = conn.execute(
            """SELECT rr.id, rr.created_at, rr.comments_count, rp.pain, rp.count, rp.share_percent
            FROM research_runs rr
            LEFT JOIN research_pain_points rp ON rp.run_id = rr.id
            WHERE rr.url = %s AND rr.owner_key_hash = %s AND rr.id <> %s
            ORDER BY rr.created_at DESC, rr.id DESC
            LIMIT 50""",
            (item.get("url"), owner, run_id),
        ).fetchall()
        conn.commit()

    previous_by_pain = {}
    previous_run_id = None
    previous_created_at = None
    previous_comments = None
    for row in previous:
        if previous_run_id is None:
            previous_run_id, previous_created_at, previous_comments = row[0], row[1], row[2]
        if row[3] is not None and row[3] not in previous_by_pain:
            previous_by_pain[row[3]] = {"count": row[4], "share_percent": row[5]}

    trends = []
    for pain in analysis.get("pain_points", []):
        label = pain.get("pain")
        prior = previous_by_pain.get(label)
        current_count = int(pain.get("count", 0))
        current_share = float(pain.get("share_percent", 0))
        count_delta = current_count - prior["count"] if prior else current_count
        share_delta = round(current_share - prior["share_percent"], 1) if prior else round(current_share, 1)
        trends.append({
            "pain": label,
            "current_count": current_count,
            "previous_count": prior["count"] if prior else 0,
            "count_delta": count_delta,
            "current_share_percent": current_share,
            "previous_share_percent": prior["share_percent"] if prior else 0,
            "share_delta_percent": share_delta,
            "status": "new" if not prior else ("rising" if count_delta > 0 or share_delta > 0 else "stable"),
        })

    rising = [x for x in trends if x["status"] in {"new", "rising"}]
    rising.sort(key=lambda x: (x["count_delta"], x["share_delta_percent"]), reverse=True)
    return {
        "run_id": run_id,
        "previous_run_id": previous_run_id,
        "previous_captured_at": previous_created_at.isoformat() if previous_created_at else None,
        "trend": trends,
        "emerging_pains": rising[:10],
        "signal": "emerging_pain_detected" if rising else "no_rising_pain",
        "comparison_note": "Operational change signal versus the immediately previous run for the same URL; not a statistical significance test.",
    }


def list_research_runs(api_key: str, url: str | None = None, limit: int = 20) -> list[dict]:
    owner = _account_hash(api_key)
    limit = max(1, min(limit, 100))
    with psycopg.connect(_db_url(), **connect_kwargs()) as conn:
        _init(conn)
        if url:
            runs = conn.execute(
                """WITH ranked AS (
                    SELECT rr.*, LAG(rr.id) OVER (PARTITION BY rr.url ORDER BY rr.created_at ASC, rr.id ASC) AS previous_run_id,
                           LAG(rr.created_at) OVER (PARTITION BY rr.url ORDER BY rr.created_at ASC, rr.id ASC) AS previous_captured_at
                    FROM research_runs rr
                    WHERE rr.owner_key_hash = %s AND rr.url = %s
                )
                SELECT id, url, source_type, market, locale, title, comments_count, created_at, previous_run_id, previous_captured_at
                FROM ranked ORDER BY created_at DESC LIMIT %s""",
                (owner, url, limit),
            ).fetchall()
        else:
            runs = conn.execute(
                """WITH ranked AS (
                    SELECT rr.*, LAG(rr.id) OVER (PARTITION BY rr.url ORDER BY rr.created_at ASC, rr.id ASC) AS previous_run_id,
                           LAG(rr.created_at) OVER (PARTITION BY rr.url ORDER BY rr.created_at ASC, rr.id ASC) AS previous_captured_at
                    FROM research_runs rr
                    WHERE rr.owner_key_hash = %s
                )
                SELECT id, url, source_type, market, locale, title, comments_count, created_at, previous_run_id, previous_captured_at
                FROM ranked ORDER BY created_at DESC LIMIT %s""",
                (owner, limit),
            ).fetchall()

        run_ids = [r[0] for r in runs]
        previous_ids = [r[8] for r in runs if r[8]]
        all_ids = list(dict.fromkeys(run_ids + previous_ids))
        pains_by_run: dict[str, list[dict]] = {run_id: [] for run_id in all_ids}
        if all_ids:
            placeholders = ",".join(["%s"] * len(all_ids))
            pain_rows = conn.execute(
                f"SELECT run_id, pain, count, share_percent FROM research_pain_points WHERE run_id IN ({placeholders}) ORDER BY count DESC",
                all_ids,
            ).fetchall()
            for row in pain_rows:
                pains_by_run[row[0]].append({"pain": row[1], "count": row[2], "share_percent": row[3]})

    output = []
    for row in runs:
        current_pains = pains_by_run.get(row[0], [])
        previous_pains = {p["pain"]: p for p in pains_by_run.get(row[8], [])} if row[8] else {}
        trends = []
        for pain in current_pains:
            prior = previous_pains.get(pain["pain"])
            count_delta = pain["count"] - prior["count"] if prior else pain["count"]
            share_delta = round(pain["share_percent"] - prior["share_percent"], 1) if prior else round(pain["share_percent"], 1)
            status = "new" if not prior else ("rising" if count_delta > 0 or share_delta > 0 else "stable")
            trends.append({
                "pain": pain["pain"],
                "count_delta": count_delta,
                "share_delta_percent": share_delta,
                "status": status,
                "current_count": pain["count"],
                "previous_count": prior["count"] if prior else 0,
                "current_share_percent": pain["share_percent"],
                "previous_share_percent": prior["share_percent"] if prior else 0,
            })
        emerging = [x for x in trends if x["status"] in {"new", "rising"}]
        emerging.sort(key=lambda x: (x["share_delta_percent"], x["count_delta"]), reverse=True)
        output.append({
            "run_id": row[0],
            "url": row[1],
            "source_type": row[2],
            "market": row[3],
            "locale": row[4],
            "title": row[5],
            "comments_count": row[6],
            "captured_at": row[7].isoformat(),
            "top_pain": current_pains[0] if current_pains else None,
            "trend": {
                "previous_run_id": row[8],
                "previous_captured_at": row[9].isoformat() if row[9] else None,
                "emerging_pains": emerging[:5],
                "signal": "emerging_pain_detected" if emerging else ("no_previous_run" if not row[8] else "no_rising_pain"),
            },
        })
    return output


def get_research_opportunity(api_key: str, run_id: str) -> dict:
    owner = _account_hash(api_key)
    with psycopg.connect(_db_url(), **connect_kwargs()) as conn:
        _init(conn)
        run = conn.execute(
            """SELECT id, url, source_type, market, locale, title, comments_count, created_at
            FROM research_runs WHERE id = %s AND owner_key_hash = %s""",
            (run_id, owner),
        ).fetchone()
        if not run:
            raise KeyError(run_id)
        pains = conn.execute(
            """SELECT pain, count, share_percent FROM research_pain_points
            WHERE run_id = %s ORDER BY count DESC LIMIT 10""",
            (run_id,),
        ).fetchall()
        examples = conn.execute(
            """SELECT body FROM research_comments WHERE run_id = %s
            ORDER BY id LIMIT 30""",
            (run_id,),
        ).fetchall()

    pain_rows = [{"pain": p[0], "count": p[1], "share_percent": p[2]} for p in pains]
    top = pain_rows[0] if pain_rows else None
    directions = []
    for p in pain_rows[:5]:
        directions.append({
            "pain": p["pain"],
            "product_direction": f"Reduce or eliminate {p['pain']}" if run[4] == "en-US" else f"「{p['pain']}」を減らす・解消する設計",
            "validation": [
                "独立した複数ソースで同じ不満が出ているか確認",
                "既存商品の低評価理由と改善余地を比較",
                "小ロット・低在庫で広告テストして反応を見る",
            ],
        })
    ad_angles = []
    for p in pain_rows[:5]:
        pain = p["pain"]
        if run[4] == "en-US":
            ad_angles.append({"pain": pain, "hook": f"Still struggling with {pain}?", "proof": f"{p['count']} comments flagged this pain."})
        else:
            ad_angles.append({"pain": pain, "hook": f"「{pain}」で困っていませんか？", "proof": f"{p['count']}件のコメントで同じ痛点を検出。"})
    return {
        "run_id": run[0],
        "source": {"url": run[1], "source_type": run[2], "market": run[3], "locale": run[4], "title": run[5]},
        "evidence": {"comments_count": run[6], "captured_at": run[7].isoformat(), "examples": [x[0] for x in examples[:10]]},
        "top_pain": top,
        "product_directions": directions,
        "ad_test_angles": ad_angles,
        "next_actions": [
            "上位痛点ごとに商品候補を検索",
            "候補商品のレビューで痛点が改善されているか再確認",
            "上位2〜3訴求を少額広告で比較",
        ],
    }


async def _enqueue_webhook(conn, monitor_id: str, event_id: str, payload: dict, now: datetime) -> None:
    import json
    conn.execute(
        """INSERT INTO webhook_deliveries
        (event_id, monitor_id, payload, status, attempts, next_attempt_at, created_at)
        VALUES (%s, %s, %s, 'pending', 0, %s, %s)
        ON CONFLICT (event_id) DO NOTHING""",
        (event_id, monitor_id, json.dumps(payload, separators=(",", ":"), ensure_ascii=False), now, now),
    )


async def _deliver_pending_webhooks() -> int:
    import json
    delivered = 0
    timeout = httpx.Timeout(10.0, connect=3.0)
    async with safe_async_client(timeout=timeout, follow_redirects=False) as client:
        while True:
            claim_token = str(uuid.uuid4())
            now = datetime.now(timezone.utc)
            with psycopg.connect(_db_url(), **connect_kwargs()) as conn:
                _init(conn)
                row = conn.execute(
                    """SELECT d.event_id, d.monitor_id, d.payload, m.webhook_url, d.attempts
                    FROM webhook_deliveries d
                    JOIN monitors m ON m.id = d.monitor_id
                    WHERE d.status = 'pending'
                      AND d.next_attempt_at <= %s
                      AND (d.locked_until IS NULL OR d.locked_until <= %s)
                    ORDER BY d.next_attempt_at, d.created_at
                    FOR UPDATE SKIP LOCKED
                    LIMIT 1""",
                    (now, now),
                ).fetchone()
                if not row:
                    break
                conn.execute(
                    """UPDATE webhook_deliveries
                    SET locked_until = %s, lease_token = %s
                    WHERE event_id = %s""",
                    (now + timedelta(seconds=30), claim_token, row[0]),
                )
                conn.commit()

            event_id, monitor_id, payload_text, webhook_url, attempts = row
            try:
                await validate_public_url(webhook_url)
                event = json.loads(payload_text)
                with psycopg.connect(_db_url(), **connect_kwargs()) as conn:
                    _init(conn)
                    lease_owned = conn.execute(
                        """SELECT 1
                        FROM webhook_deliveries
                        WHERE event_id = %s
                          AND lease_token = %s
                          AND locked_until > CURRENT_TIMESTAMP
                        FOR UPDATE""",
                        (event_id, claim_token),
                    ).fetchone()
                    if not lease_owned:
                        continue
                async with client.stream(
                    "POST", webhook_url, json=event,
                    headers={"X-EC-Pulse-Event-ID": event_id},
                ) as response:
                    response.raise_for_status()
                    await read_response_bytes(response, MAX_WEBHOOK_RESPONSE_BYTES)
                with psycopg.connect(_db_url(), **connect_kwargs()) as conn:
                    cursor = conn.execute(
                        """UPDATE webhook_deliveries
                        SET status='delivered', delivered_at=%s, locked_until=NULL,
                            lease_token=NULL, last_error=NULL
                        WHERE event_id=%s AND lease_token=%s""",
                        (datetime.now(timezone.utc), event_id, claim_token),
                    )
                    conn.commit()
                if cursor.rowcount != 1:
                    continue
                delivered += 1
            except Exception as exc:
                attempts += 1
                delay = min(3600, 60 * (2 ** min(attempts - 1, 6)))
                with psycopg.connect(_db_url(), **connect_kwargs()) as conn:
                    conn.execute(
                        """UPDATE webhook_deliveries
                        SET attempts=%s, next_attempt_at=%s, locked_until=NULL,
                            lease_token=NULL, last_error=%s
                        WHERE event_id=%s AND lease_token=%s""",
                        (
                            attempts,
                            datetime.now(timezone.utc) + timedelta(seconds=delay),
                            f"{type(exc).__name__}: {exc}"[:500],
                            event_id,
                            claim_token,
                        ),
                    )
                    conn.commit()
    return delivered


async def run_due_monitors() -> dict:
    from app.services.product_parser import fetch_product
    now = datetime.now(timezone.utc)
    with psycopg.connect(_db_url(), **connect_kwargs()) as conn:
        _init(conn)
        rows = conn.execute(
            """SELECT id, url, interval_minutes, webhook_url, last_price, last_checked_at
            FROM monitors
            WHERE last_checked_at IS NULL
               OR last_checked_at <= %s - (interval_minutes * INTERVAL '1 minute')""",
            (now,),
        ).fetchall()
    checked = changed = failed = 0
    for monitor_id, url, interval, webhook_url, old_price, last_checked_at in rows:
        lease_token = str(uuid.uuid4())
        try:
            with psycopg.connect(_db_url(), **connect_kwargs()) as lease_conn:
                lease_row = lease_conn.execute(
                    """INSERT INTO monitor_run_leases (monitor_id, lease_token, locked_until)
                    VALUES (%s, %s, CURRENT_TIMESTAMP + INTERVAL '10 minutes')
                    ON CONFLICT (monitor_id) DO UPDATE
                    SET lease_token = EXCLUDED.lease_token,
                        locked_until = EXCLUDED.locked_until
                    WHERE monitor_run_leases.locked_until <= CURRENT_TIMESTAMP
                    RETURNING lease_token""",
                    (monitor_id, lease_token),
                ).fetchone()
                lease_conn.commit()
            if not lease_row:
                continue

            await validate_public_url(webhook_url)
            data = await fetch_product(url)
            pricing = data.get("pricing", {})
            new_price = pricing.get("price")
            currency = pricing.get("currency")
            source = data.get("source", {})
            source_url = source.get("url") or url

            with psycopg.connect(_db_url(), **connect_kwargs()) as conn:
                _init(conn)
                lease_owned = conn.execute(
                    """UPDATE monitor_run_leases
                    SET locked_until = CURRENT_TIMESTAMP + INTERVAL '10 minutes'
                    WHERE monitor_id = %s
                      AND lease_token = %s
                      AND locked_until > CURRENT_TIMESTAMP
                    RETURNING lease_token""",
                    (monitor_id, lease_token),
                ).fetchone()
                if not lease_owned:
                    continue

                conn.execute(
                    "INSERT INTO price_history (monitor_id, price, currency, captured_at, source_url) VALUES (%s, %s, %s, %s, %s)",
                    (monitor_id, new_price, currency, data["captured_at"], source_url),
                )
                if old_price is not None and new_price is not None and new_price != old_price:
                    event_id = str(uuid.uuid5(
                        uuid.NAMESPACE_URL,
                        f"ec-pulse:monitor:{monitor_id}:{last_checked_at.isoformat() if last_checked_at else 'initial'}:{old_price}:{new_price}",
                    ))
                    event = {
                        "event": "price_changed",
                        "event_id": event_id,
                        "monitor_id": monitor_id,
                        "old_price": old_price,
                        "new_price": new_price,
                        "change_amount": round(new_price - old_price, 2),
                        "change_percent": round(((new_price - old_price) / old_price) * 100, 2) if old_price else None,
                        "direction": "down" if new_price < old_price else "up",
                        "currency": currency,
                        "url": url,
                        "source": {"site": source.get("site"), "url": source_url},
                        "captured_at": data["captured_at"],
                    }
                    await _enqueue_webhook(conn, monitor_id, event_id, event, now)
                    changed += 1
                conn.execute(
                    "UPDATE monitors SET last_price = %s, last_checked_at = %s WHERE id = %s",
                    (new_price, now, monitor_id),
                )
                conn.commit()
            checked += 1
        except Exception:
            failed += 1
        finally:
            try:
                with psycopg.connect(_db_url(), **connect_kwargs()) as lease_conn:
                    lease_conn.execute(
                        "DELETE FROM monitor_run_leases WHERE monitor_id = %s AND lease_token = %s",
                        (monitor_id, lease_token),
                    )
                    lease_conn.commit()
            except Exception:
                pass

    delivered = await _deliver_pending_webhooks()
    return {"checked": checked, "changed": changed, "failed": failed, "webhooks_delivered": delivered}
