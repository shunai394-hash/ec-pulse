import asyncio
import hashlib
import os
import secrets
import httpx
import psycopg
from app.services.db import connect_kwargs
from datetime import datetime, timezone

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request, Response
from fastapi.security import APIKeyHeader
from pydantic import BaseModel, Field, constr, HttpUrl

from app.services.billing import cancel_subscription, create_checkout, create_customer_portal, process_webhook
from app.services.monitor_store import consume_credit, create_monitor, create_monitor_with_credit, ensure_api_account, get_account_usage, get_price_history, get_price_opportunity, list_monitors, run_due_monitors, validate_api_key, save_research_run, get_research_opportunity, list_research_runs, provision_customer_api_key, list_customer_api_keys, revoke_customer_api_key, get_customer_usage, get_customer_usage_alert
from app.services.product_cache import fetch_product_cached
from app.services.product_search import search_products
from app.services.patrol import run_patrol
from app.services.consumer_insights import analyze_comments
from app.services.research_ingest import fetch_public_comments
from app.services.rate_limit import check_rate_limit
from app.services.request_signature import verify_request_signature
from app.services.url_safety import validate_public_url
from app.services.google_auth import current_user, exchange_callback, google_login, logout

app = FastAPI(
    title="EC Pulse API",
    description="Commerce data, product discovery, price monitoring, and market research infrastructure.",
    version="0.12.0",
    docs_url="/docs",
    redoc_url="/redoc",
)
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)
MAX_STRIPE_WEBHOOK_BYTES = 2 * 1024 * 1024

@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response


class ProductRequest(BaseModel):
    url: HttpUrl
class ProductCompareRequest(BaseModel):
    urls: list[HttpUrl] = Field(min_length=2, max_length=20)
class ProductSearchRequest(BaseModel):
    query: str = Field(min_length=1, max_length=200)
    marketplaces: list[str] = Field(default=["amazon", "rakuten", "yahoo"], min_length=1, max_length=3)
    limit: int = Field(default=5, ge=1, le=10)
class ConsumerInsightRequest(BaseModel):
    comments: list[constr(max_length=2000)] = Field(min_length=1, max_length=5000)
    source: str | None = Field(default=None, max_length=50)
class ResearchUrlRequest(BaseModel):
    urls: list[HttpUrl] = Field(min_length=1, max_length=20)
    max_comments_per_url: int = Field(default=500, ge=1, le=500)

class MonitorRequest(BaseModel):
    url: HttpUrl
    interval_minutes: int = Field(default=60, ge=5, le=10080)
    webhook_url: HttpUrl

class CustomerKeyRequest(BaseModel):
    rotate: bool = False

def _key_hash(api_key: str) -> str:
    return hashlib.sha256(api_key.encode()).hexdigest()

async def get_api_key(request: Request, api_key: str | None = Depends(api_key_header)) -> str:
    if not api_key:
        raise HTTPException(status_code=401, detail="Missing API key")
    try:
        if not validate_api_key(api_key):
            raise HTTPException(status_code=401, detail="Invalid or revoked API key")
        require_signature = os.getenv("EC_PULSE_REQUIRE_REQUEST_SIGNATURE", "").lower() in {"1", "true", "yes"}
        timestamp = request.headers.get("X-EC-Timestamp")
        signature = request.headers.get("X-EC-Signature")
        if require_signature or timestamp or signature:
            body = await request.body()
            try:
                verify_request_signature(
                    api_key,
                    timestamp,
                    signature,
                    request.method,
                    request.url.path,
                    body,
                )
            except ValueError as exc:
                raise HTTPException(status_code=401, detail=str(exc)) from exc
        account = ensure_api_account(api_key)
        rate = check_rate_limit(_key_hash(api_key), account["plan"])
        request.state.rate_limit = rate
        if not rate["allowed"]:
            raise HTTPException(status_code=429, detail="Rate limit exceeded", headers={"Retry-After": str(rate["reset_seconds"]), "X-RateLimit-Limit": str(rate["limit"]), "X-RateLimit-Remaining": "0"})
    except HTTPException:
        raise
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    return api_key

def _charge(api_key: str, endpoint: str, credits: int = 1):
    try: return consume_credit(api_key, endpoint, credits)
    except RuntimeError as exc:
        message=str(exc)
        if "Insufficient API credits" in message: raise HTTPException(status_code=402, detail=message) from exc
        if "Invalid or revoked API key" in message: raise HTTPException(status_code=401, detail=message) from exc
        raise HTTPException(status_code=503, detail=message) from exc

def _consumer_insight_credit_cost(comment_count: int) -> int:
    return max(1, (comment_count + 49) // 50)


def _research_opportunity_credit_cost(query_count: int, marketplaces: int = 3, limit: int = 5) -> int:
    """Mirror the existing product-search credit unit for internal opportunity searches."""
    if query_count < 0 or marketplaces < 1 or limit < 1:
        raise ValueError("query_count, marketplaces, and limit must be positive")
    return max(1, query_count * marketplaces * limit)


def _usage_headers(request: Request, api_key: str, credits_used: int | None = None) -> dict[str,str]:
    try:
        account = ensure_api_account(api_key)
        rate = getattr(request.state, "rate_limit", None)
        if rate is None:
            rate = check_rate_limit(_key_hash(api_key), account["plan"])
            request.state.rate_limit = rate
        headers = {
            "X-RateLimit-Limit": str(rate["limit"]),
            "X-RateLimit-Remaining": str(rate["remaining"]),
            "X-RateLimit-Reset": str(rate["reset_seconds"]),
            "X-EC-Credits-Remaining": str(account["credits_balance"]),
        }
        if credits_used is not None:
            headers["X-EC-Credits-Used"] = str(credits_used)
        return headers
    except Exception:
        return {}

async def _validate_urls(urls: list[str]) -> None:
    for url in urls:
        try:
            await validate_public_url(url)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=f"Invalid public URL: {exc}") from exc


async def _fetch_product_or_http_error(url: str):
    try:
        payload,cache_hit=await fetch_product_cached(url)
        return {**payload,"cache":{"hit":cache_hit,"ttl_seconds":300}}
    except ValueError as exc: raise HTTPException(status_code=400,detail=str(exc)) from exc
    except Exception as exc: raise HTTPException(status_code=502,detail=f"Unable to retrieve product page: {type(exc).__name__}") from exc

@app.get("/auth/google", include_in_schema=False)
async def auth_google():
    return await google_login()


@app.get("/auth/callback", include_in_schema=False)
async def auth_callback(request: Request, code: str | None = None):
    if not code:
        raise HTTPException(status_code=400, detail="Missing OAuth code")
    return await exchange_callback(request, code)


@app.get("/auth/me", tags=["auth"])
async def auth_me(request: Request):
    return {"user": await current_user(request)}


@app.post("/auth/logout", include_in_schema=False)
def auth_logout():
    return logout()


@app.get("/")
def root():
    return {"name":"EC Pulse API","version":"0.12.0","status":"ok","docs":"/docs","health":"/health","pricing_model":"credit-based API with per-plan rate limits"}

@app.get("/health")
def health():
    # Verify the database dependency so a broken deployment is not reported as healthy.
    # The response explains *why* the database is unavailable (error class and
    # connection shape) without exposing host, user or password.
    from app.services.db import classify_db_error, describe_db_url
    commit = os.getenv("VERCEL_GIT_COMMIT_SHA")
    try:
        from app.services.monitor_store import _db_url
        with psycopg.connect(_db_url(), **connect_kwargs(), connect_timeout=3) as conn:
            conn.execute("SELECT 1")
        return {"status": "ok", "database": "ok", "commit": commit}
    except Exception as exc:
        raise HTTPException(
            status_code=503,
            detail={
                "status": "degraded",
                "database": "unavailable",
                "error": type(exc).__name__,
                "reason": classify_db_error(exc),
                "connection": describe_db_url(),
                "commit": commit,
            },
        ) from exc

@app.get("/billing", include_in_schema=False)
async def billing_page(request: Request):
    user = await current_user(request)
    user_id = user.get("id")
    if not user_id:
        raise HTTPException(status_code=401, detail="Authenticated user id is missing")
    return {"service": "EC Pulse API", "billing": "/v1/customer/account", "status": "authenticated"}


@app.get("/billing/success", include_in_schema=False)
async def billing_success(request: Request, session_id: str | None = Query(default=None)):
    user = await current_user(request)
    user_id = user.get("id")
    if not user_id:
        raise HTTPException(status_code=401, detail="Authenticated user id is missing")
    try:
        from app.services.monitor_store import _init, _db_url
        with psycopg.connect(_db_url(), **connect_kwargs()) as conn:
            _init(conn)
            row = conn.execute(
                """SELECT plan, credits_balance, subscription_status,
                          stripe_customer_id, stripe_subscription_id,
                          current_period_start, current_period_end,
                          cancel_at_period_end
                   FROM api_accounts
                   WHERE customer_user_id = %s""",
                (user_id,),
            ).fetchone()
        if not row:
            return {"status": "pending", "message": "Payment received. Waiting for subscription webhook."}
        return {
            "status": "active" if row[2] in {"active", "trialing", "past_due"} else "pending",
            "plan": row[0],
            "credits_balance": row[1],
            "subscription_status": row[2],
            "current_period_start": row[5].isoformat() if row[5] else None,
            "current_period_end": row[6].isoformat() if row[6] else None,
            "cancel_at_period_end": bool(row[7]),
        }
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


@app.get("/billing/cancel", include_in_schema=False)
async def billing_cancel_page(request: Request):
    user = await current_user(request)
    if not user.get("id"):
        raise HTTPException(status_code=401, detail="Authenticated user id is missing")
    return {"status": "cancelled", "message": "Checkout was cancelled. No subscription change was applied."}


@app.post("/v1/customer/key", tags=["customer"])
async def customer_key(request: CustomerKeyRequest, http_request: Request):
    user = await current_user(http_request)
    user_id = user.get("id")
    if not user_id:
        raise HTTPException(status_code=401, detail="Authenticated user id is missing")
    try:
        return provision_customer_api_key(user_id, rotate=request.rotate)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc

@app.get("/v1/customer/keys", tags=["customer"])
async def customer_keys(http_request: Request):
    user = await current_user(http_request)
    user_id = user.get("id")
    if not user_id:
        raise HTTPException(status_code=401, detail="Authenticated user id is missing")
    try:
        return {"keys": list_customer_api_keys(user_id)}
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


@app.post("/v1/customer/keys/revoke", tags=["customer"])
async def customer_revoke_key(http_request: Request, key_prefix: str = Query(..., min_length=8, max_length=32)):
    user = await current_user(http_request)
    user_id = user.get("id")
    if not user_id:
        raise HTTPException(status_code=401, detail="Authenticated user id is missing")
    try:
        revoked = revoke_customer_api_key(user_id, key_prefix)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    if not revoked:
        raise HTTPException(status_code=404, detail="Active API key not found")
    return {"revoked": True, "key_prefix": key_prefix}


@app.get("/v1/customer/usage", tags=["customer"])
async def customer_usage(http_request: Request, days: int = Query(default=30, ge=1, le=365)):
    user = await current_user(http_request)
    user_id = user.get("id")
    if not user_id:
        raise HTTPException(status_code=401, detail="Authenticated user id is missing")
    try:
        return get_customer_usage(user_id, days=days)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


@app.get("/v1/customer/usage/alerts", tags=["customer"])
async def customer_usage_alerts(http_request: Request):
    user = await current_user(http_request)
    user_id = user.get("id")
    if not user_id:
        raise HTTPException(status_code=401, detail="Authenticated user id is missing")
    try:
        return get_customer_usage_alert(user_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


@app.get("/v1/customer/account", tags=["customer"])
async def customer_account(http_request: Request):
    user = await current_user(http_request)
    user_id = user.get("id")
    if not user_id:
        raise HTTPException(status_code=401, detail="Authenticated user id is missing")
    try:
        from app.services.monitor_store import _init, _db_url
        with psycopg.connect(_db_url(), **connect_kwargs()) as conn:
            _init(conn)
            row = conn.execute(
                "SELECT plan, credits_balance FROM api_accounts WHERE customer_user_id = %s",
                (user_id,),
            ).fetchone()
            if not row:
                return {"provisioned": False, "plan": "free", "credits_balance": 0, "key_prefix": None}
            key = conn.execute(
                "SELECT key_prefix FROM api_keys WHERE account_key_hash = (SELECT api_key_hash FROM api_accounts WHERE customer_user_id = %s) AND active = TRUE ORDER BY created_at DESC LIMIT 1",
                (user_id,),
            ).fetchone()
        return {"provisioned": bool(key), "plan": row[0], "credits_balance": row[1], "key_prefix": key[0] if key else None}
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc

@app.post("/v1/billing/checkout")
def billing_checkout(plan: str = Query(..., pattern="^(pro|business)$"), api_key: str = Depends(get_api_key)):
    try:
        return {"url": create_checkout(api_key, plan), "plan": plan}
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc

@app.post("/v1/billing/cancel", tags=["billing"])
def billing_cancel(at_period_end: bool = Query(default=True), api_key: str = Depends(get_api_key)):
    try:
        return cancel_subscription(api_key, at_period_end=at_period_end)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc

@app.post("/v1/billing/portal")
def billing_portal(api_key: str = Depends(get_api_key)):
    try:
        return {"url": create_customer_portal(api_key)}
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc

@app.post("/api/stripe/webhook")
@app.post("/api/webhooks/stripe")
async def stripe_webhook(request: Request, stripe_signature: str | None = Header(default=None, alias="Stripe-Signature")):
    if not stripe_signature:
        raise HTTPException(status_code=400, detail="Missing Stripe-Signature header")
    content_length = request.headers.get("content-length")
    if content_length:
        try:
            if int(content_length) > MAX_STRIPE_WEBHOOK_BYTES:
                raise HTTPException(status_code=413, detail="Stripe webhook payload is too large")
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid Content-Length header")
    body = await request.body()
    if len(body) > MAX_STRIPE_WEBHOOK_BYTES:
        raise HTTPException(status_code=413, detail="Stripe webhook payload is too large")
    try:
        return process_webhook(body, stripe_signature)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc

@app.get("/v1/pricing", tags=["billing"])
def pricing():
    return {
        "billing": "credit_based",
        "pricing_source": "stripe",
        "plans": {
            "free": {"credits": 100, "rate_limit_per_minute": 30},
            "pro": {"credits": "configurable", "rate_limit_per_minute": 300},
            "business": {"credits": "configurable", "rate_limit_per_minute": 3000},
        },
        "checkout": {
            "pro": "/v1/billing/checkout?plan=pro",
            "business": "/v1/billing/checkout?plan=business",
        },
        "customer_portal": "/v1/billing/portal",
        "cancel_subscription": "/v1/billing/cancel",
    }

@app.post("/v1/consumer-insights/analyze")
def consumer_insights(request: ConsumerInsightRequest, request_http: Request, response: Response, api_key: str = Depends(get_api_key)):
    charge = _charge(api_key, "POST /v1/consumer-insights/analyze", _consumer_insight_credit_cost(len(request.comments)))
    for k, v in _usage_headers(request_http, api_key, charge).items():
        response.headers[k] = v
    result = analyze_comments(request.comments, request.source, "en-US" if request.source and any(x in request.source.lower() for x in ["amazon.com", "reddit", "youtube.com", "tiktok.com"]) else None)
    result["credits"] = charge
    return result

@app.post("/v1/research/ingest")
async def research_ingest(request: ResearchUrlRequest, request_http: Request, response: Response, api_key: str = Depends(get_api_key)):
    await _validate_urls([str(url) for url in request.urls])
    charge = _charge(api_key, "POST /v1/research/ingest", len(request.urls))
    for k, v in _usage_headers(request_http, api_key, charge).items():
        response.headers[k] = v
    results = []
    for url in request.urls:
        try:
            item = await fetch_public_comments(str(url), request.max_comments_per_url)
            if item["comments"]:
                item["analysis"] = analyze_comments(item["comments"], item["source"], item.get("locale"))
                try:
                    item["trend"] = save_research_run(api_key, item, item["analysis"])
                except Exception as exc:
                    item["trend"] = {"signal": "persistence_error", "error": type(exc).__name__}
            else:
                item["analysis"] = {"comments_analyzed": 0, "pain_points": [], "top_terms": [], "recommended_angle": None}
            results.append(item)
        except httpx.HTTPStatusError as exc:
            results.append({"url": str(url), "ok": False, "error": f"http_{exc.response.status_code}"})
        except Exception as exc:
            results.append({"url": str(url), "ok": False, "error": type(exc).__name__})
    market_summary = {}
    for item in results:
        if not item.get("analysis"):
            continue
        market = item.get("market", "GLOBAL")
        bucket = market_summary.setdefault(market, {"urls": 0, "comments": 0, "pain_points": {}})
        bucket["urls"] += 1
        bucket["comments"] += item["analysis"].get("comments_analyzed", 0)
        for pain in item["analysis"].get("pain_points", []):
            bucket["pain_points"][pain["pain"]] = bucket["pain_points"].get(pain["pain"], 0) + pain["count"]

    for bucket in market_summary.values():
        bucket["top_pains"] = sorted(
            [{"pain": pain, "count": count} for pain, count in bucket["pain_points"].items()],
            key=lambda x: x["count"],
            reverse=True,
        )[:10]
        del bucket["pain_points"]

    return {"count": len(results), "credits": charge, "market_summary": market_summary, "results": results}

@app.get("/v1/research/runs")
def research_runs(
    request_http: Request,
    url: str | None = Query(default=None, max_length=2000),
    limit: int = Query(default=20, ge=1, le=100),
    api_key: str = Depends(get_api_key),
):
    try:
        return {"runs": list_research_runs(api_key, url, limit)}
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


@app.get("/v1/research/runs/{run_id}/opportunity")
async def research_opportunity(run_id: str, request_http: Request, response: Response, api_key: str = Depends(get_api_key)):
    try:
        result = get_research_opportunity(api_key, run_id)
        queries = []
        for item in result.get("product_directions", [])[:3]:
            if item["pain"] not in queries:
                queries.append(item["pain"])
        charge = _charge(
            api_key,
            "GET /v1/research/runs/{run_id}/opportunity",
            _research_opportunity_credit_cost(len(queries), marketplaces=3, limit=5),
        )
        for k, v in _usage_headers(request_http, api_key, charge).items():
            response.headers[k] = v
        candidates = []
        for query in queries:
            try:
                found = await search_products(query, ["amazon", "rakuten", "yahoo"], 5)
                if isinstance(found, dict):
                    candidates.extend(found.get("results", found.get("items", [])))
            except Exception:
                continue
        result["product_candidates"] = candidates[:15]
        result["credits"] = charge
        return result
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Research run not found") from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc

@app.get("/v1/products")
async def product_get(request:Request,response:Response,url:HttpUrl=Query(...),api_key:str=Depends(get_api_key)):
    await _validate_urls([str(url)])
    charge=_charge(api_key,"GET /v1/products")
    for k,v in _usage_headers(request,api_key,charge).items(): response.headers[k]=v
    result = await _fetch_product_or_http_error(str(url))
    result["credits"] = charge
    return result

@app.post("/v1/products")
async def product_post(request_http:Request,response:Response,request:ProductRequest,api_key:str=Depends(get_api_key)):
    await _validate_urls([str(request.url)])
    charge=_charge(api_key,"POST /v1/products")
    for k,v in _usage_headers(request_http,api_key,charge).items(): response.headers[k]=v
    result = await _fetch_product_or_http_error(str(request.url))
    result["credits"] = charge
    return result

@app.post("/v1/products/search")
async def product_search(request_http:Request,response:Response,request:ProductSearchRequest,api_key:str=Depends(get_api_key)):
    marketplaces=[m.lower() for m in request.marketplaces]
    if any(m not in {"amazon","rakuten","yahoo"} for m in marketplaces): raise HTTPException(status_code=400,detail="marketplaces must contain only amazon, rakuten, yahoo")
    if len(set(marketplaces)) != len(marketplaces): raise HTTPException(status_code=400,detail="marketplaces must not contain duplicates")
    charge=_charge(api_key,"POST /v1/products/search",request.limit*len(marketplaces))
    for k,v in _usage_headers(request_http,api_key,charge).items(): response.headers[k]=v
    try:
        result = await search_products(request.query, marketplaces, request.limit)
        result["credits"] = charge
        return result
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Product search failed: {type(exc).__name__}") from exc

@app.post("/v1/products/compare")
async def product_compare(request_http:Request,response:Response,request:ProductCompareRequest,api_key:str=Depends(get_api_key)):
    urls=[str(u) for u in request.urls]
    await _validate_urls(urls)
    charge=_charge(api_key,"POST /v1/products/compare",len(urls))
    for k,v in _usage_headers(request_http,api_key,charge).items(): response.headers[k]=v
    results=await asyncio.gather(*(fetch_product_cached(url) for url in urls),return_exceptions=True)
    products=[]
    for url,result in zip(urls,results):
        if isinstance(result,Exception): products.append({"url":url,"ok":False,"error":type(result).__name__}); continue
        payload,cache_hit=result; products.append({"url":url,"ok":True,"cache":{"hit":cache_hit,"ttl_seconds":300},"product":payload})
    successful=[x["product"] for x in products if x["ok"]]
    ranked=sorted(successful,key=lambda x:(x.get("pricing",{}).get("price") is None,x.get("pricing",{}).get("price") or float("inf")))
    return {"count":len(products),"successful":len(successful),"credits":charge,"results":products,"price_ranking":[{"rank":i,"url":x.get("source",{}).get("url"),"title":x.get("product",{}).get("title"),"price":x.get("pricing",{}).get("price"),"currency":x.get("pricing",{}).get("currency"),"marketplace":x.get("source",{}).get("marketplace"),"product_id":x.get("source",{}).get("product_id")} for i,x in enumerate(ranked,1)]}

@app.post("/v1/monitors")
async def monitor(request_http:Request,response:Response,request:MonitorRequest,api_key:str=Depends(get_api_key)):
    try:
        await validate_public_url(str(request.url))
        await validate_public_url(str(request.webhook_url))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=f"Invalid monitor or webhook URL: {exc}") from exc
    try:
        result, charge = create_monitor_with_credit(
            api_key=api_key,
            url=str(request.url),
            interval_minutes=request.interval_minutes,
            webhook_url=str(request.webhook_url),
            endpoint="POST /v1/monitors",
        )
        for k,v in _usage_headers(request_http,api_key,charge).items(): response.headers[k]=v
        result["credits"] = charge
        return result
    except RuntimeError as exc:
        message = str(exc)
        if "Insufficient API credits" in message:
            raise HTTPException(status_code=402, detail=message) from exc
        if "Invalid or revoked API key" in message:
            raise HTTPException(status_code=401, detail=message) from exc
        raise HTTPException(status_code=503, detail=message) from exc

@app.get("/v1/monitors")
def monitors(api_key:str=Depends(get_api_key)):
    try: return {"monitors":list_monitors(api_key)}
    except RuntimeError as exc: raise HTTPException(status_code=503,detail=str(exc)) from exc

@app.get("/v1/monitors/{monitor_id}/history")
def monitor_history(monitor_id:str, request_http:Request, response:Response, limit:int=100,api_key:str=Depends(get_api_key)):
    if not 1<=limit<=1000: raise HTTPException(status_code=400,detail="limit must be between 1 and 1000")
    try:
        result = get_price_history(api_key,monitor_id,limit)
        charge = _charge(api_key,"GET /v1/monitors/{monitor_id}/history")
        for k,v in _usage_headers(request_http,api_key,charge).items(): response.headers[k]=v
        result["credits"] = charge
        return result
    except KeyError as exc: raise HTTPException(status_code=404,detail="Monitor not found") from exc
    except RuntimeError as exc: raise HTTPException(status_code=503,detail=str(exc)) from exc

@app.get("/v1/monitors/{monitor_id}/opportunity")
def monitor_opportunity(monitor_id:str, request_http:Request, response:Response, limit:int=100,api_key:str=Depends(get_api_key)):
    if not 2<=limit<=1000: raise HTTPException(status_code=400,detail="limit must be between 2 and 1000")
    try:
        result = get_price_opportunity(api_key,monitor_id,limit)
        charge = _charge(api_key,"GET /v1/monitors/{monitor_id}/opportunity",2)
        for k,v in _usage_headers(request_http,api_key,charge).items(): response.headers[k]=v
        result["credits"] = charge
        return result
    except KeyError as exc: raise HTTPException(status_code=404,detail="Monitor not found") from exc
    except RuntimeError as exc: raise HTTPException(status_code=503,detail=str(exc)) from exc

@app.get("/v1/account", tags=["account"])
def account(request: Request, response: Response, api_key: str = Depends(get_api_key)):
    try:
        ensure_api_account(api_key)
        usage = get_account_usage(api_key)
        for key, value in _usage_headers(request, api_key).items():
            response.headers[key] = value
        return usage
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc

@app.get("/api/cron/patrol/latest")
async def patrol_latest(authorization: str | None = Header(default=None), limit: int = Query(default=10, ge=1, le=50)):
    secret = (os.getenv("CRON_SECRET") or "").strip()
    if not secret or not authorization or not secrets.compare_digest(authorization, f"Bearer {secret}"):
        raise HTTPException(status_code=401, detail="Unauthorized")
    try:
        from app.services.monitor_store import _db_url
        with psycopg.connect(_db_url(), **connect_kwargs(), connect_timeout=3) as conn:
            rows = conn.execute(
                "SELECT id, checked_at, ok, report FROM patrol_reports ORDER BY checked_at DESC LIMIT %s",
                (limit,),
            ).fetchall()
        return {
            "count": len(rows),
            "reports": [
                {"id": row[0], "checked_at": row[1].isoformat(), "ok": row[2], "report": row[3]}
                for row in rows
            ],
        }
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Patrol report unavailable: {type(exc).__name__}") from exc

@app.get("/api/cron/patrol")
async def patrol(authorization: str | None = Header(default=None)):
    secret = (os.getenv("CRON_SECRET") or "").strip()
    if not secret or not authorization or not secrets.compare_digest(authorization, f"Bearer {secret}"):
        raise HTTPException(status_code=401, detail="Unauthorized")
    report = await run_patrol()
    return report

@app.get("/api/cron/check-monitors")
async def check_monitors(authorization:str|None=Header(default=None)):
    secret=(os.getenv("CRON_SECRET") or "").strip()
    if not secret or not authorization or not secrets.compare_digest(authorization, f"Bearer {secret}"): raise HTTPException(status_code=401,detail="Unauthorized")
    try: return {"ok":True,"checked_at":datetime.now(timezone.utc).isoformat(),**await run_due_monitors()}
    except RuntimeError as exc: raise HTTPException(status_code=503,detail=str(exc)) from exc
