import psycopg
import pytest
from fastapi.testclient import TestClient

from app.services import db
from app.services.db import classify_db_error, connect_kwargs, describe_db_url, normalize_db_url


def test_trailing_newline_and_quotes_are_removed():
    url = normalize_db_url('"postgresql://u:p@db.example.com:5432/postgres"\n')
    assert url.startswith("postgresql://u:p@db.example.com:5432/postgres?")
    assert "\n" not in url and '"' not in url
    assert "connect_timeout=5" in url


def test_supabase_hosts_default_to_ssl_require_but_keep_explicit_mode():
    assert "sslmode=require" in normalize_db_url("postgresql://u:p@aws-0-ap-northeast-1.pooler.supabase.com:6543/postgres")
    assert "sslmode=verify-full" in normalize_db_url("postgresql://u:p@db.abc.supabase.co:5432/postgres?sslmode=verify-full")
    assert "sslmode" not in normalize_db_url("postgresql://u:p@localhost:5432/app")


def test_missing_url_raises_runtime_error(monkeypatch):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    with pytest.raises(RuntimeError):
        db.database_url()
    monkeypatch.setenv("DATABASE_URL", "  \n")
    with pytest.raises(RuntimeError):
        db.database_url()


def test_transaction_pooler_disables_prepared_statements(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "postgresql://postgres.ref:p@aws-0-x.pooler.supabase.com:6543/postgres")
    assert connect_kwargs() == {"prepare_threshold": None}
    monkeypatch.setenv("DATABASE_URL", "postgresql://postgres.ref:p@aws-0-x.pooler.supabase.com:5432/postgres")
    assert connect_kwargs() == {}


def test_describe_never_exposes_credentials_or_host():
    info = describe_db_url("postgresql://postgres:SECRETPW@db.abcdefgh.supabase.co:5432/postgres\n")
    assert info["host_kind"] == "supabase_direct"
    assert info["had_surrounding_whitespace_or_quotes"] is True
    assert "SECRETPW" not in str(info) and "abcdefgh" not in str(info)
    assert describe_db_url("postgresql://postgres.ref:p@aws-0-x.pooler.supabase.com:6543/postgres")["host_kind"] == "supabase_pooler_transaction"
    assert describe_db_url("") == {"configured": False}


@pytest.mark.parametrize("message,reason", [
    ("connection failed: Network is unreachable", "network_unreachable_ipv6_likely_use_supabase_pooler"),
    ('could not translate host name "db.x.supabase.co" to address', "dns_resolution_failed"),
    ("FATAL: Tenant or user not found", "pooler_user_must_be_postgres.<project_ref>"),
    ('FATAL: password authentication failed for user "postgres"', "authentication_failed"),
    ("connection timeout expired", "connect_timeout"),
    ("DATABASE_URL is not configured", "database_url_missing"),
])
def test_error_classification(message, reason):
    assert classify_db_error(psycopg.OperationalError(message)) == reason


def test_health_reports_reason_without_secrets(monkeypatch):
    from app.main import app

    def boom(*_args, **_kwargs):
        raise psycopg.OperationalError("connection to server failed: Network is unreachable")

    monkeypatch.setenv("DATABASE_URL", "postgresql://postgres:TOPSECRET@db.abcdefgh.supabase.co:5432/postgres")
    monkeypatch.setattr(psycopg, "connect", boom)
    response = TestClient(app).get("/health")
    assert response.status_code == 503
    detail = response.json()["detail"]
    assert detail["database"] == "unavailable"
    assert detail["reason"] == "network_unreachable_ipv6_likely_use_supabase_pooler"
    assert detail["connection"]["host_kind"] == "supabase_direct"
    assert "TOPSECRET" not in response.text and "abcdefgh" not in response.text


def test_health_ok(monkeypatch):
    from app.main import app

    class Conn:
        def __enter__(self):
            return self

        def __exit__(self, *_):
            return False

        def execute(self, *_args):
            return None

    seen = {}

    def connect(url, **kwargs):
        seen.update(kwargs, url=url)
        return Conn()

    monkeypatch.setenv("DATABASE_URL", "postgresql://postgres.ref:p@aws-0-x.pooler.supabase.com:6543/postgres\n")
    monkeypatch.setattr(psycopg, "connect", connect)
    response = TestClient(app).get("/health")
    assert response.status_code == 200
    assert response.json()["database"] == "ok"
    assert seen["prepare_threshold"] is None
    assert "sslmode=require" in seen["url"] and not seen["url"].endswith("\n")
