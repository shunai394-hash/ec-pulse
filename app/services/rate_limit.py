import os
from datetime import datetime, timezone

import psycopg
from app.services.db import connect_kwargs, database_url

_WINDOWS = {"free": 60, "pro": 60, "business": 60}
_LIMITS = {"free": 30, "pro": 300, "business": 3000}


def _db_url() -> str:
    return database_url()


def check_rate_limit(api_key_hash: str, plan: str) -> dict:
    """Enforce an atomic shared fixed-window limit in Postgres."""
    window = _WINDOWS.get(plan, 60)
    limit = _LIMITS.get(plan, 30)

    with psycopg.connect(_db_url(), **connect_kwargs()) as conn:
        now = datetime.now(timezone.utc)
        current_window = now.replace(second=0, microsecond=0)
        row = conn.execute(
            """
            INSERT INTO api_rate_limits (api_key_hash, window_start, request_count)
            VALUES (%s, %s, 1)
            ON CONFLICT (api_key_hash) DO UPDATE
            SET window_start = EXCLUDED.window_start,
                request_count = CASE
                    WHEN api_rate_limits.window_start = EXCLUDED.window_start
                    THEN LEAST(api_rate_limits.request_count + 1, %s)
                    ELSE 1
                END
            RETURNING window_start, request_count
            """,
            (api_key_hash, current_window, limit + 1),
        ).fetchone()

    request_count = row[1]
    elapsed = max(0, (now - row[0]).total_seconds())
    reset_seconds = max(1, int(window - elapsed))

    return {
        "allowed": request_count <= limit,
        "limit": limit,
        "remaining": max(0, limit - request_count),
        "reset_seconds": reset_seconds,
    }
