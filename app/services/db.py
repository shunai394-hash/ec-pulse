"""Shared PostgreSQL connection settings for Vercel serverless.

Common production failure modes this module addresses:

* DATABASE_URL pasted with a trailing newline / surrounding quotes -> libpq
  cannot parse it, so every request fails while the database itself is fine.
* Supabase direct host (db.<ref>.supabase.co) resolves to IPv6 only; Vercel
  functions have no IPv6 egress, so connections fail. The Supavisor pooler
  (*.pooler.supabase.com) must be used instead.
* Supavisor transaction mode (port 6543) does not keep server-side prepared
  statements between transactions, so psycopg auto-prepare must be disabled.
* No connect timeout -> a network problem hangs until the function timeout.
"""

import os
import re
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

DEFAULT_CONNECT_TIMEOUT = 5


def normalize_db_url(raw: str | None) -> str:
    url = (raw or "").strip().strip('"').strip("'").strip()
    if not url:
        raise RuntimeError("DATABASE_URL is not configured")
    parts = urlsplit(url)
    if parts.scheme not in {"postgres", "postgresql"}:
        return url
    query = dict(parse_qsl(parts.query, keep_blank_values=True))
    host = (parts.hostname or "").lower()
    if host.endswith(".supabase.co") or host.endswith(".supabase.com"):
        query.setdefault("sslmode", "require")
    query.setdefault("connect_timeout", str(DEFAULT_CONNECT_TIMEOUT))
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query), parts.fragment))


def database_url() -> str:
    return normalize_db_url(os.getenv("DATABASE_URL"))


def describe_db_url(raw: str | None = None) -> dict:
    """Non-secret description of the configured connection (no user/password/host)."""
    value = (raw if raw is not None else os.getenv("DATABASE_URL")) or ""
    stripped = value.strip().strip('"').strip("'").strip()
    if not stripped:
        return {"configured": False}
    parts = urlsplit(stripped)
    host = (parts.hostname or "").lower()
    try:
        port = parts.port or 5432
    except ValueError:
        port = None
    if host.endswith(".pooler.supabase.com"):
        kind = "supabase_pooler_transaction" if port == 6543 else "supabase_pooler_session"
    elif re.fullmatch(r"db\.[a-z0-9]+\.supabase\.co", host):
        kind = "supabase_direct"
    elif host:
        kind = "other"
    else:
        kind = "unparseable"
    query = dict(parse_qsl(parts.query, keep_blank_values=True))
    return {
        "configured": True,
        "had_surrounding_whitespace_or_quotes": stripped != value,
        "scheme": parts.scheme,
        "host_kind": kind,
        "port": port,
        "sslmode": query.get("sslmode") or ("require (default)" if "supabase" in host else None),
        "has_password": bool(parts.password),
    }


def connect_kwargs() -> dict:
    """Extra psycopg.connect kwargs for the configured endpoint."""
    try:
        port = urlsplit(database_url()).port
    except (RuntimeError, ValueError):
        return {}
    # Transaction pooling (pgbouncer / Supavisor :6543): disable auto-prepare.
    if port == 6543:
        return {"prepare_threshold": None}
    return {}


def classify_db_error(exc: BaseException) -> str:
    text = f"{type(exc).__name__}: {exc}".lower()
    rules = [
        ("database_url is not configured", "database_url_missing"),
        ("invalid dsn", "database_url_invalid"),
        ("missing \"=\"", "database_url_invalid"),
        ("network is unreachable", "network_unreachable_ipv6_likely_use_supabase_pooler"),
        ("cannot assign requested address", "network_unreachable_ipv6_likely_use_supabase_pooler"),
        ("could not translate host name", "dns_resolution_failed"),
        ("name or service not known", "dns_resolution_failed"),
        ("tenant or user not found", "pooler_user_must_be_postgres.<project_ref>"),
        ("password authentication failed", "authentication_failed"),
        ("no pg_hba.conf entry", "authentication_failed"),
        ("ssl", "ssl_negotiation_failed"),
        ("timeout", "connect_timeout"),
        ("timed out", "connect_timeout"),
        ("connection refused", "connection_refused"),
        ("too many connections", "too_many_connections_use_pooler"),
        ("max client connections", "too_many_connections_use_pooler"),
        ("prepared statement", "prepared_statement_conflict_transaction_pooler"),
    ]
    for needle, reason in rules:
        if needle in text:
            return reason
    return "unknown"
