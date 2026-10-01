import json
import os
from datetime import datetime, timezone

import httpx
import psycopg
from app.services.db import connect_kwargs

from app.services.product_search import search_products
from app.services.monitor_store import run_due_monitors, _db_url
from app.services.patrol_ai import diagnose


def _store_report(report: dict) -> None:
    with psycopg.connect(_db_url(), **connect_kwargs(), connect_timeout=3) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS patrol_reports (
                id BIGSERIAL PRIMARY KEY,
                checked_at TIMESTAMPTZ NOT NULL,
                ok BOOLEAN NOT NULL,
                report JSONB NOT NULL
            )
        """)
        conn.execute(
            "INSERT INTO patrol_reports (checked_at, ok, report) VALUES (%s, %s, %s)",
            (report["checked_at"], report["ok"], json.dumps(report, ensure_ascii=False)),
        )
        conn.commit()


async def _send_report(report: dict) -> bool:
    webhook = os.getenv("PATROL_REPORT_WEBHOOK_URL")
    if not webhook:
        return True
    try:
        async with httpx.AsyncClient(timeout=8, follow_redirects=False) as client:
            response = await client.post(webhook, json=report)
            response.raise_for_status()
        return True
    except Exception:
        return False


async def run_patrol() -> dict:
    checks = []
    repairs = []
    try:
        with psycopg.connect(_db_url(), **connect_kwargs(), connect_timeout=3) as conn:
            conn.execute("SELECT 1")
        checks.append({"name": "database", "ok": True})
    except Exception as exc:
        checks.append({"name": "database", "ok": False, "error": type(exc).__name__})

    queries = ["日焼け止め レディース", "UVカット 日焼け対策", "夏 レディース UV", "日焼け対策 グッズ レディース", "UVカット アームカバー"]
    search_result = None
    errors = []
    for index, query in enumerate(queries):
        try:
            result = await search_products(query, ["amazon", "rakuten", "yahoo"], 3)
            items = result.get("results", result.get("items", [])) if isinstance(result, dict) else []
            if items:
                search_result = {"query": query, "count": len(items)}
                checks.append({"name": "product-search", "ok": True, **search_result})
                if index > 0:
                    repairs.append({"type": "search-query-fallback", "action": "alternate_query", "query": query})
                break
        except Exception as exc:
            errors.append(type(exc).__name__)
    if search_result is None:
        checks.append({"name": "product-search", "ok": False, "error": "all smoke-test queries returned zero products", "exceptions": errors[-3:]})
        repairs.append({"type": "search-degraded", "action": "escalate", "reason": "all bounded fallback queries returned zero products"})

    try:
        monitor_result = await run_due_monitors()
        checks.append({"name": "monitors", "ok": True, "result": monitor_result})
    except Exception as exc:
        checks.append({"name": "monitors", "ok": False, "error": type(exc).__name__})
        try:
            retry_result = await run_due_monitors()
            repairs.append({"type": "monitor-retry", "action": "retry_once", "result": retry_result})
            checks.append({"name": "monitors-retry", "ok": True, "result": retry_result})
        except Exception as retry_exc:
            repairs.append({"type": "monitor-failure", "action": "escalate", "error": type(retry_exc).__name__})

    failures = [item for item in checks if item.get("ok") is False]
    diagnosis = await diagnose(checks, repairs)

    # Execute only allowlisted AI actions. No arbitrary code or shell execution.
    if "retry_monitors" in diagnosis.get("actions", []) and not any(r.get("type") == "monitor-retry" for r in repairs):
        try:
            retry_result = await run_due_monitors()
            repairs.append({"type": "ai-monitor-retry", "action": "retry_monitors", "result": retry_result})
            checks.append({"name": "ai-monitor-retry", "ok": True, "result": retry_result})
        except Exception as exc:
            repairs.append({"type": "ai-monitor-retry-failure", "action": "escalate", "error": type(exc).__name__})
    if "retry_search" in diagnosis.get("actions", []) and not any(r.get("type") == "search-query-fallback" for r in repairs):
        try:
            retry = await search_products("UVカット レディース 日焼け対策", ["amazon", "rakuten", "yahoo"], 3)
            items = retry.get("results", retry.get("items", [])) if isinstance(retry, dict) else []
            checks.append({"name": "ai-search-retry", "ok": bool(items), "count": len(items)})
            repairs.append({"type": "ai-search-retry", "action": "retry_search", "count": len(items)})
        except Exception as exc:
            repairs.append({"type": "ai-search-retry-failure", "action": "escalate", "error": type(exc).__name__})

    failures = [item for item in checks if item.get("ok") is False]
    report = {
        "ok": not failures,
        "agent": "patrol-ai",
        "mode": "observe-repair-report",
        "repair_policy": "allowlisted-retry-only",
        "ai_diagnosis": diagnosis,
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "checks": checks,
        "repairs": repairs,
        "failures": failures,
        "summary": "巡回正常。修復不要。" if not failures and not repairs else "巡回完了。自己修復を実施または要監視状態を報告。",
    }
    try:
        _store_report(report)
    except Exception as exc:
        report["ok"] = False
        report["repairs"].append({"type": "report-persistence-failure", "action": "escalate", "error": type(exc).__name__})
        report["failures"].append({"name": "report-persistence", "ok": False, "error": type(exc).__name__})

    delivered = await _send_report(report)
    report["report_delivery"] = {
        "webhook_configured": bool(os.getenv("PATROL_REPORT_WEBHOOK_URL")),
        "delivered": delivered,
    }
    if not delivered:
        report["ok"] = False
        report["repairs"].append({"type": "report-delivery-failure", "action": "escalate", "error": "webhook_delivery_failed"})
        report["failures"].append({"name": "report-delivery", "ok": False, "error": "webhook_delivery_failed"})
    return report
