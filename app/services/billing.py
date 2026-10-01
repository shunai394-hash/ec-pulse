import os
import uuid
from datetime import datetime, timedelta, timezone

import psycopg
from app.services.db import connect_kwargs
import stripe

from app.services.monitor_store import _account_hash, _db_url

PLANS = {
    "pro": ("STRIPE_PRICE_PRO", "STRIPE_PRO_PRICE_ID"),
    "business": ("STRIPE_PRICE_BUSINESS", "STRIPE_BUSINESS_PRICE_ID"),
}

def _price_id(plan: str) -> str | None:
    for env_name in PLANS.get(plan, ()):
        value = os.getenv(env_name)
        if value:
            return value
    return None

SCHEMA = """
CREATE TABLE IF NOT EXISTS billing_events (
    event_id TEXT PRIMARY KEY,
    event_type TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    processed_at TIMESTAMPTZ NOT NULL,
    payload JSONB NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_billing_events_created ON billing_events (created_at DESC);
"""


def _init_billing(conn):
    conn.execute(SCHEMA)
    conn.execute("ALTER TABLE api_accounts ADD COLUMN IF NOT EXISTS stripe_customer_id TEXT")
    conn.execute("ALTER TABLE api_accounts ADD COLUMN IF NOT EXISTS stripe_subscription_id TEXT")
    conn.execute("ALTER TABLE api_accounts ADD COLUMN IF NOT EXISTS subscription_status TEXT")
    conn.execute("ALTER TABLE api_accounts ADD COLUMN IF NOT EXISTS cancel_at_period_end BOOLEAN NOT NULL DEFAULT FALSE")
    conn.execute("ALTER TABLE api_accounts ADD COLUMN IF NOT EXISTS current_period_start TIMESTAMPTZ")
    conn.execute("ALTER TABLE api_accounts ADD COLUMN IF NOT EXISTS current_period_end TIMESTAMPTZ")
    conn.execute("ALTER TABLE api_accounts ADD COLUMN IF NOT EXISTS last_stripe_event_created BIGINT")
    conn.execute("ALTER TABLE api_accounts ADD COLUMN IF NOT EXISTS last_stripe_event_id TEXT")
    conn.execute("ALTER TABLE api_accounts ADD COLUMN IF NOT EXISTS stripe_subscription_created_at BIGINT")
    conn.execute("ALTER TABLE api_accounts ADD COLUMN IF NOT EXISTS checkout_pending_key TEXT")
    conn.execute("ALTER TABLE api_accounts ADD COLUMN IF NOT EXISTS checkout_pending_until TIMESTAMPTZ")
    conn.execute("ALTER TABLE api_accounts ADD COLUMN IF NOT EXISTS checkout_session_id TEXT")
    conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_api_accounts_stripe_customer ON api_accounts (stripe_customer_id) WHERE stripe_customer_id IS NOT NULL")
    conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_api_accounts_stripe_subscription ON api_accounts (stripe_subscription_id) WHERE stripe_subscription_id IS NOT NULL")
    conn.commit()


def _stripe():
    key = os.getenv("STRIPE_SECRET_KEY")
    if not key:
        raise RuntimeError("STRIPE_SECRET_KEY is not configured")
    stripe.api_key = key
    return stripe


def _ts(value):
    return datetime.fromtimestamp(value, tz=timezone.utc) if value else None


def _price_plan(price_id: str | None) -> str | None:
    if not price_id:
        return None
    for plan, env_names in PLANS.items():
        if any(price_id == os.getenv(env_name) for env_name in env_names):
            return plan
    return None


def _account_by_customer(conn, customer_id: str):
    return conn.execute("SELECT api_key_hash FROM api_accounts WHERE stripe_customer_id = %s", (customer_id,)).fetchone()


def _apply_subscription(conn, subscription, event_created: int | None = None):
    customer_id = subscription.get("customer")
    subscription_id = subscription.get("id")
    status = subscription.get("status")
    items = subscription.get("items", {}).get("data", [])
    price_id = items[0].get("price", {}).get("id") if items else None
    plan = _price_plan(price_id)
    row = _account_by_customer(conn, customer_id) if customer_id else None
    if not row:
        return False
    event_id = subscription.get("_ec_pulse_event_id")
    state = conn.execute(
        """SELECT stripe_subscription_id, subscription_status,
                  last_stripe_event_created, last_stripe_event_id,
                  stripe_subscription_created_at
           FROM api_accounts
           WHERE api_key_hash = %s
           FOR UPDATE""",
        (row[0],),
    ).fetchone()
    if event_created is not None and state:
        previous_subscription_id, previous_status, previous_created, _previous_event_id, previous_subscription_created_at = state
        if (
            previous_subscription_id
            and subscription_id
            and subscription_id == previous_subscription_id
            and previous_created is not None
            and event_created is not None
            and event_created < previous_created
        ):
            return False
        # A customer can have more than one Stripe subscription. Once this
        # account is on a live subscription, a terminal event for a different
        # (older) subscription must never replace the current subscription.
        # This also protects against equal-timestamp events, whose IDs are not
        # chronological and therefore cannot be used as a tie-breaker.
        active_statuses = {"active", "trialing", "past_due"}
        if (
            previous_subscription_id
            and subscription_id
            and subscription_id != previous_subscription_id
            and previous_status in active_statuses
            and status not in active_statuses
        ):
            return False
        subscription_created_at = subscription.get("created")
        if (
            previous_subscription_id
            and subscription_id
            and subscription_id != previous_subscription_id
            and previous_subscription_created_at is not None
            and subscription_created_at is not None
            and subscription_created_at <= previous_subscription_created_at
        ):
            return False
        if (
            previous_subscription_id
            and subscription_id
            and subscription_id != previous_subscription_id
            and previous_status in active_statuses
            and previous_created is not None
            and event_created <= previous_created
        ):
            return False
    active_statuses = {"active", "trialing", "past_due"}
    # Never silently downgrade a live Stripe subscription to the free plan when
    # its Price ID is unknown or not configured locally. That would turn a
    # billing configuration mistake into an unintended loss of paid state.
    if status in active_statuses and plan is None:
        raise RuntimeError("Stripe subscription uses an unrecognized price")
    effective_plan = plan if status in active_statuses else None
    if effective_plan:
        conn.execute("""UPDATE api_accounts SET plan=%s, stripe_subscription_id=%s, subscription_status=%s,
            current_period_start=%s, current_period_end=%s, cancel_at_period_end=%s, stripe_subscription_created_at=%s, last_stripe_event_created=%s, last_stripe_event_id=%s, updated_at=%s WHERE api_key_hash=%s""", (effective_plan, subscription_id, status, _ts(subscription.get("current_period_start")), _ts(subscription.get("current_period_end")), bool(subscription.get("cancel_at_period_end", False)), subscription.get("created"), event_created, event_id, datetime.now(timezone.utc), row[0]))
    else:
        conn.execute("""UPDATE api_accounts SET plan=%s, stripe_subscription_id=%s, subscription_status=%s,
            current_period_start=%s, current_period_end=%s, cancel_at_period_end=%s, last_stripe_event_created=%s, last_stripe_event_id=%s, updated_at=%s WHERE api_key_hash=%s""", (effective_plan or "free", subscription_id, status, _ts(subscription.get("current_period_start")), _ts(subscription.get("current_period_end")), bool(subscription.get("cancel_at_period_end", False)), event_created, event_id, datetime.now(timezone.utc), row[0]))
    return True


def process_webhook(payload: bytes, signature: str) -> dict:
    secret = os.getenv("STRIPE_WEBHOOK_SECRET")
    if not secret:
        raise RuntimeError("STRIPE_WEBHOOK_SECRET is not configured")
    sdk = _stripe()
    event = sdk.Webhook.construct_event(payload, signature, secret)
    event_data = event.to_dict_recursive()
    event_id = event_data["id"]
    event_type = event_data["type"]
    now = datetime.now(timezone.utc)
    with psycopg.connect(_db_url(), **connect_kwargs()) as conn:
        _init_billing(conn)
        inserted = conn.execute("""INSERT INTO billing_events (event_id,event_type,created_at,processed_at,payload)
            VALUES (%s,%s,%s,%s,%s) ON CONFLICT (event_id) DO NOTHING RETURNING event_id""",
            (event_id, event_type, _ts(event_data.get("created")) or now, now, event_data)).fetchone()
        if not inserted:
            return {"ok": True, "duplicate": True, "event_id": event_id}
        obj = event_data.get("data", {}).get("object", {})
        handled = False
        subscription_event_types = {
            "customer.subscription.created",
            "customer.subscription.updated",
            "customer.subscription.deleted",
            "customer.subscription.paused",
            "customer.subscription.resumed",
        }
        invoice_sync_types = {
            "invoice.paid",
            "invoice.payment_succeeded",
            "invoice.payment_failed",
            "invoice.payment_action_required",
        }
        if event_type in subscription_event_types:
            subscription_id = obj.get("id")
            current = obj
            if subscription_id:
                try:
                    current = sdk.Subscription.retrieve(subscription_id).to_dict_recursive()
                except Exception as exc:
                    if event_type != "customer.subscription.deleted":
                        raise RuntimeError("Unable to retrieve Stripe subscription") from exc
            current = {**current, "_ec_pulse_event_id": event_id}
            handled = _apply_subscription(conn, current, event_data.get("created"))
        elif event_type in invoice_sync_types:
            subscription_id = obj.get("subscription")
            if subscription_id:
                try:
                    current = sdk.Subscription.retrieve(subscription_id).to_dict_recursive()
                except Exception as exc:
                    raise RuntimeError("Unable to retrieve Stripe subscription") from exc
                current = {**current, "_ec_pulse_event_id": event_id}
                handled = _apply_subscription(conn, current, event_data.get("created"))
        elif event_type == "checkout.session.completed":
            customer_id = obj.get("customer")
            metadata = obj.get("metadata") or {}
            api_key_hash = metadata.get("api_key_hash")
            checkout_key = metadata.get("checkout_pending_key")
            if customer_id and api_key_hash and checkout_key:
                pending = conn.execute(
                    "SELECT checkout_pending_key, checkout_pending_until, stripe_customer_id FROM api_accounts WHERE api_key_hash=%s FOR UPDATE",
                    (api_key_hash,),
                ).fetchone()
                if not pending:
                    return {"ok": True, "duplicate": False, "event_id": event_id, "type": event_type, "handled": False}
                pending_key_matches = pending[0] == checkout_key
                pending_active = pending[1] is not None and pending[1] > now
                customer_matches = pending[2] is None or pending[2] == customer_id
                if not customer_matches:
                    # A stale Checkout Session must not replace a customer linked by a newer checkout.
                    return {"ok": True, "duplicate": False, "event_id": event_id, "type": event_type, "handled": False}
                if not pending_key_matches and pending_active:
                    # A newer Checkout is still within its recovery window. The old
                    # completed session must not claim the account before the newer
                    # session finishes or expires.
                    return {"ok": True, "duplicate": False, "event_id": event_id, "type": event_type, "handled": False}
                if pending_key_matches:
                    conn.execute(
                        "UPDATE api_accounts SET stripe_customer_id=%s, checkout_pending_key=NULL, checkout_pending_until=NULL, updated_at=%s WHERE api_key_hash=%s AND checkout_pending_key=%s",
                        (customer_id, now, api_key_hash, checkout_key),
                    )
                else:
                    # The pending lease may have expired, but this Checkout can still be a
                    # real successful payment. Link its customer without consuming a newer checkout.
                    conn.execute(
                        "UPDATE api_accounts SET stripe_customer_id=%s, updated_at=%s WHERE api_key_hash=%s AND (stripe_customer_id IS NULL OR stripe_customer_id=%s)",
                        (customer_id, now, api_key_hash, customer_id),
                    )
                handled = True
                subscription_id = obj.get("subscription")
                if subscription_id:
                    try:
                        subscription = sdk.Subscription.retrieve(subscription_id)
                    except Exception as exc:
                        # Do not acknowledge a transient Stripe API failure.
                        # Rolling back lets Stripe retry the webhook later.
                        raise RuntimeError("Unable to retrieve Stripe subscription") from exc
                    handled = _apply_subscription(
                        conn,
                        {**subscription.to_dict_recursive(), "_ec_pulse_event_id": event_id},
                        event_data.get("created"),
                    ) or handled
        conn.commit()
    return {"ok": True, "duplicate": False, "event_id": event_id, "type": event_type, "handled": handled}


def cancel_subscription(api_key: str, at_period_end: bool = True) -> dict:
    """Cancel the account's current Stripe subscription.

    Cancellation is requested in Stripe first; the webhook remains the source
    of truth for the local subscription state. By default the customer keeps
    access until the already-paid billing period ends.
    """
    from app.services.monitor_store import _account_hash

    key_hash = _account_hash(api_key)
    with psycopg.connect(_db_url(), **connect_kwargs()) as conn:
        _init_billing(conn)
        row = conn.execute(
            """SELECT stripe_customer_id, stripe_subscription_id, subscription_status,
                      current_period_end, cancel_at_period_end
               FROM api_accounts a
            JOIN api_keys k ON k.account_key_hash = a.api_key_hash
               WHERE k.api_key_hash=%s AND k.active=TRUE
               FOR UPDATE OF a""",
            (key_hash,),
        ).fetchone()
        if not row or not row[1]:
            raise ValueError("No active Stripe subscription is linked to this account")
        customer_id, subscription_id, status, period_end, already_scheduled = row
        if status in {"canceled", "incomplete_expired", "unpaid"}:
            raise ValueError("No active Stripe subscription is linked to this account")
        if at_period_end and already_scheduled:
            return {
                "subscription_id": subscription_id,
                "status": status,
                "cancel_at_period_end": True,
                "current_period_end": period_end.isoformat() if period_end else None,
            }
        try:
            if at_period_end:
                subscription = _stripe().Subscription.modify(
                    subscription_id,
                    cancel_at_period_end=True,
                    idempotency_key=f"ec-pulse-cancel-{subscription_id}-period-end",
                )
            else:
                subscription = _stripe().Subscription.delete(
                    subscription_id,
                    idempotency_key=f"ec-pulse-cancel-{subscription_id}-immediate",
                )
        except Exception as exc:
            conn.rollback()
            raise RuntimeError("Unable to cancel Stripe subscription") from exc
        conn.commit()

    return {
        "subscription_id": subscription.get("id", subscription_id),
        "status": subscription.get("status", status),
        "cancel_at_period_end": bool(subscription.get("cancel_at_period_end", at_period_end)),
        "current_period_end": _ts(subscription.get("current_period_end")),
    }


def create_customer_portal(api_key: str) -> str:
    base_url = os.getenv("APP_BASE_URL")
    if not base_url:
        raise RuntimeError("APP_BASE_URL is not configured")
    from app.services.monitor_store import _account_hash
    with psycopg.connect(_db_url(), **connect_kwargs()) as conn:
        _init_billing(conn)
        row = conn.execute(
            """SELECT a.stripe_customer_id
            FROM api_keys k
            JOIN api_accounts a ON a.api_key_hash = k.account_key_hash
            WHERE k.api_key_hash=%s AND k.active=TRUE""",
            (_account_hash(api_key),),
        ).fetchone()
    customer_id = row[0] if row else None
    if not customer_id:
        raise ValueError("No Stripe customer is linked to this account")
    session = _stripe().billing_portal.Session.create(
        customer=customer_id,
        return_url=f"{base_url}/billing"
    )
    return session.url


def create_checkout(api_key: str, plan: str) -> str:
    if plan not in PLANS:
        raise ValueError("plan must be pro or business")
    price_id = _price_id(plan)
    base_url = os.getenv("APP_BASE_URL")
    if not price_id or not base_url:
        raise RuntimeError("Stripe price and APP_BASE_URL are not configured")
    from app.services.monitor_store import _account_hash
    with psycopg.connect(_db_url(), **connect_kwargs()) as conn:
        _init_billing(conn)
        key_hash = _account_hash(api_key)
        row = conn.execute(
            """SELECT a.api_key_hash, a.stripe_customer_id, a.stripe_subscription_id,
                      a.subscription_status, a.checkout_pending_key, a.checkout_pending_until,
                      a.checkout_session_id
               FROM api_keys k
               JOIN api_accounts a ON a.api_key_hash = k.account_key_hash
               WHERE k.api_key_hash=%s AND k.active=TRUE
               FOR UPDATE OF a""",
            (key_hash,),
        ).fetchone()
        account_hash = row[0] if row else None
        customer_id = row[1] if row else None
        if row and row[2] and row[3] in {"active", "trialing", "past_due"}:
            raise ValueError("An active Stripe subscription is already linked to this account")
        now = datetime.now(timezone.utc)
        if not row:
            raise ValueError("Invalid or revoked API key")
        if row[4] and row[5]:
            if row[5] > now:
                raise ValueError("A Stripe checkout is already in progress for this account")
            old_session_id = row[6]
            if old_session_id:
                try:
                    old_session = _stripe().checkout.Session.retrieve(old_session_id)
                    old_status = old_session.get("status") if hasattr(old_session, "get") else getattr(old_session, "status", None)
                    if old_status == "complete":
                        raise RuntimeError("Previous Stripe checkout completed; waiting for webhook")
                    if old_status == "open":
                        _stripe().checkout.Session.expire(old_session_id)
                except RuntimeError:
                    raise
                except Exception as exc:
                    raise RuntimeError("Unable to reconcile expired Stripe checkout") from exc
            conn.execute(
                "UPDATE api_accounts SET checkout_pending_key=NULL, checkout_pending_until=NULL, checkout_session_id=NULL, updated_at=%s WHERE api_key_hash=%s",
                (now, account_hash),
            )
        checkout_key = str(uuid.uuid4())
        pending_until = now + timedelta(minutes=10)
        conn.execute(
            "UPDATE api_accounts SET checkout_pending_key=%s, checkout_pending_until=%s, updated_at=%s WHERE api_key_hash=%s",
            (checkout_key, pending_until, now, account_hash),
        )
        conn.commit()

    params = {"mode": "subscription", "line_items": [{"price": price_id, "quantity": 1}], "success_url": f"{base_url}/billing/success?session_id={{CHECKOUT_SESSION_ID}}", "cancel_url": f"{base_url}/billing/cancel", "metadata": {"api_key_hash": account_hash, "checkout_pending_key": checkout_key, "plan": plan}}
    if customer_id:
        params["customer"] = customer_id
    try:
        session = _stripe().checkout.Session.create(
            **params,
            idempotency_key=f"ec-pulse-checkout-{checkout_key}",
        )
        session_id = session.get("id") if hasattr(session, "get") else getattr(session, "id", None)
        if not session_id:
            raise RuntimeError("Stripe checkout did not return a session id")
        with psycopg.connect(_db_url(), **connect_kwargs()) as conn:
            _init_billing(conn)
            conn.execute(
                "UPDATE api_accounts SET checkout_session_id=%s, updated_at=%s WHERE api_key_hash=%s AND checkout_pending_key=%s",
                (session_id, datetime.now(timezone.utc), account_hash, checkout_key),
            )
            conn.commit()
    except Exception:
        try:
            if "session_id" in locals() and session_id:
                _stripe().checkout.Session.expire(session_id)
        except Exception:
            pass
        with psycopg.connect(_db_url(), **connect_kwargs()) as conn:
            _init_billing(conn)
            conn.execute(
                "UPDATE api_accounts SET checkout_pending_key=NULL, checkout_pending_until=NULL, checkout_session_id=NULL, updated_at=%s WHERE api_key_hash=%s AND checkout_pending_key=%s",
                (datetime.now(timezone.utc), account_hash, checkout_key),
            )
            conn.commit()
        raise
    return session.url
