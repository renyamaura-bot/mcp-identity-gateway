"""
Okta IAM Meaning Engine MCP Server (Semantic + Risk + Vectorized Context)

Features:
- analyze_identity_state(user, time_range_hours, reason)
    - Fetches System Logs via Okta Workflows
    - Normalizes Okta System Log events into a semantic schema
    - Applies heuristic risk analysis
    - Summarizes events into text and generates embeddings
    - Stores the summary and embedding in a local JSONL vector store
    - Searches for similar past cases and returns them as context

All credentials are supplied via environment variables; this file
does not contain any hard-coded secrets.
"""

import os
import json
import uuid
import math
import logging
from typing import Any, Dict, List, Optional, Tuple

import requests
from fastmcp import FastMCP
from openai import OpenAI

# ==== MCP instance ====
mcp = FastMCP("Okta Meaning Engine (Vectorized)")
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

SEMANTIC_EVENT_VERSION = "1.0"

# ==== OpenAI client ====
_openai_client: Optional[OpenAI] = None


def get_openai_client() -> OpenAI:
    """
    Lazily initialize and return a shared OpenAI client instance.
    """
    global _openai_client
    if _openai_client is None:
        _openai_client = OpenAI()
    return _openai_client


# ============================================================
# A/B: Semantic normalization (System Log -> Semantic Event)
# ============================================================

ACTOR_TYPE_MAP = {
    "User": "user",
    "SystemPrincipal": "system",
    "AppInstance": "application",
}

TARGET_TYPE_MAP = {
    "User": "user",
    "AppInstance": "application",
    "Group": "group",
    "Policy": "policy",
    "email": "email",
}


def classify_category(event_type: Optional[str]) -> str:
    """
    Map Okta eventType to a high-level semantic category.
    """
    if not event_type:
        return "other"

    if event_type.startswith("user.authentication."):
        return "authentication"
    if event_type.startswith("user.mfa."):
        return "mfa"
    if event_type.startswith("user.session."):
        return "session"
    if event_type.startswith("user.lifecycle."):
        return "user_lifecycle"
    if event_type.startswith("user.account."):
        return "user_account"
    if event_type.startswith("system.email."):
        return "email"

    parts = event_type.split(".")
    return parts[0] if parts else "other"


def normalize_actor(raw_actor: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Normalize the actor block from Okta System Log into a uniform shape.
    """
    if not raw_actor:
        return {
            "id": None,
            "type": None,
            "raw_type": None,
            "login": None,
            "display_name": None,
        }

    raw_type = raw_actor.get("type")
    norm_type = ACTOR_TYPE_MAP.get(raw_type, "other")

    return {
        "id": raw_actor.get("id"),
        "type": norm_type,
        "raw_type": raw_type,
        "login": raw_actor.get("alternateId"),
        "display_name": raw_actor.get("displayName"),
    }


def normalize_primary_target(
    raw_targets: Optional[List[Dict[str, Any]]],
) -> Optional[Dict[str, Any]]:
    """
    Normalize the first (primary) target in the Okta event.
    """
    if not raw_targets:
        return None

    primary = raw_targets[0] or {}
    raw_type = primary.get("type")
    norm_type = TARGET_TYPE_MAP.get(raw_type, "other")

    return {
        "id": primary.get("id"),
        "type": norm_type,
        "raw_type": raw_type,
        "alternate_id": primary.get("alternateId"),
        "display_name": primary.get("displayName"),
    }


def extract_subject_user(
    actor: Dict[str, Any],
    raw_targets: Optional[List[Dict[str, Any]]],
) -> Optional[Dict[str, Any]]:
    """
    Determine which user should be treated as the "subject" of the event.

    Priority:
      1. If any target has type "User", use that as subject_user.
      2. Otherwise, if actor.type == "user", treat actor as subject_user.
      3. If none applies, return None.
    """
    if raw_targets:
        for t in raw_targets:
            if not t or not isinstance(t, dict):
                continue
            if t.get("type") == "User":
                return {
                    "id": t.get("id"),
                    "login": t.get("alternateId"),
                    "display_name": t.get("displayName"),
                    "role": "target",
                }

    if actor.get("type") == "user":
        return {
            "id": actor.get("id"),
            "login": actor.get("login"),
            "display_name": actor.get("display_name"),
            "role": "actor",
        }

    return None


def normalize_client(raw_client: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Normalize the client block (IP / UA / geo) of the event.
    """
    if not raw_client:
        return {
            "ip": None,
            "device": None,
            "zone": None,
            "user_agent": {"raw": None, "os": None, "browser": None},
            "geo": {
                "city": None,
                "state": None,
                "country": None,
                "postal_code": None,
                "latitude": None,
                "longitude": None,
            },
        }

    ua = raw_client.get("userAgent") or {}
    geo = raw_client.get("geographicalContext") or {}
    geo_loc = geo.get("geolocation") or {}

    return {
        "ip": raw_client.get("ipAddress"),
        "device": raw_client.get("device"),
        "zone": raw_client.get("zone"),
        "user_agent": {
            "raw": ua.get("rawUserAgent"),
            "os": ua.get("os"),
            "browser": ua.get("browser"),
        },
        "geo": {
            "city": geo.get("city"),
            "state": geo.get("state"),
            "country": geo.get("country"),
            "postal_code": geo.get("postalCode"),
            "latitude": geo_loc.get("lat"),
            "longitude": geo_loc.get("lon"),
        },
    }


def normalize_request(
    raw_request: Optional[Dict[str, Any]],
    debug_context: Optional[Dict[str, Any]],
    auth_context: Optional[Dict[str, Any]],
    transaction: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    """
    Normalize request / transaction context into a compact structure.
    """
    ip_chain = (raw_request or {}).get("ipChain") or []
    first_ip = None
    if ip_chain:
        first = ip_chain[0] or {}
        first_ip = first.get("ip")

    debug_data = (debug_context or {}).get("debugData") or {}

    return {
        "ip": first_ip,
        "uri": debug_data.get("requestUri"),
        "url": debug_data.get("url"),
        "transaction_id": (transaction or {}).get("id"),
        "transaction_type": (transaction or {}).get("type"),
        "session_id": (auth_context or {}).get("rootSessionId"),
    }


def normalize_outcome(raw_outcome: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Normalize event outcome information.
    """
    if not raw_outcome:
        return {"result": None, "reason": None}
    return {
        "result": raw_outcome.get("result"),
        "reason": raw_outcome.get("reason"),
    }


def normalize_okta_event(raw_entry: Dict[str, Any]) -> Dict[str, Any]:
    """
    Normalize one Okta System Log event into the semantic event schema.

    For Okta Workflows integrations, it is assumed that the raw event
    is stored under "Raw Output". If not present, raw_entry is treated
    as the event itself.
    """
    raw = raw_entry.get("Raw Output") or raw_entry

    event_type = raw.get("eventType")
    category = classify_category(event_type)
    parts = event_type.split(".") if event_type else []
    action = parts[-1] if parts else None

    actor_norm = normalize_actor(raw.get("actor"))
    targets_raw = raw.get("target") or []
    primary_target = normalize_primary_target(targets_raw)
    subject_user = extract_subject_user(actor_norm, targets_raw)

    client_norm = normalize_client(raw.get("client"))
    request_norm = normalize_request(
        raw_request=raw.get("request"),
        debug_context=raw.get("debugContext"),
        auth_context=raw.get("authenticationContext"),
        transaction=raw.get("transaction"),
    )
    outcome_norm = normalize_outcome(raw.get("outcome"))

    semantic = {
        "version": SEMANTIC_EVENT_VERSION,
        "event_id": raw.get("uuid"),
        "event_time": raw.get("published"),
        "event_type": event_type,
        "category": category,
        "action": action,
        "display_message": raw.get("displayMessage"),
        "severity": raw.get("severity"),
        "legacy_event_type": raw.get("legacyEventType"),
        "actor": actor_norm,
        "primary_target": primary_target,
        "subject_user": subject_user,
        "client": client_norm,
        "request": request_norm,
        "outcome": outcome_norm,
    }

    return semantic


# ============================================================
# C: Simple heuristic risk analysis
# ============================================================


def analyze_risk(
    semantic_events: List[Dict[str, Any]],
    user_login: str,
    time_range_hours: int,
) -> Dict[str, Any]:
    """
    Simple non-ML heuristic risk analysis.

    Signals:
    - Number of authentication failures
    - Presence of MFA-related events
    - Password reset activity
    - High-severity events

    Returns a coarse risk_level and suggested actions.
    """
    failed_auth = 0
    mfa_events = 0
    password_resets = 0
    high_severity = 0

    reasons: List[str] = []
    notable_events: List[str] = []

    for ev in semantic_events:
        etype = ev.get("event_type") or ""
        cat = ev.get("category") or ""
        sev = ev.get("severity") or ""
        out = ev.get("outcome") or {}
        result = (out.get("result") or "").upper()

        if cat == "authentication" and result == "FAILURE":
            failed_auth += 1
            notable_events.append(f"Auth failure: {etype}")

        if "user.mfa." in etype:
            mfa_events += 1
            notable_events.append(f"MFA event: {etype}")

        if etype.startswith("user.account.reset") or "password_reset" in (
            ev.get("legacy_event_type") or ""
        ):
            password_resets += 1
            notable_events.append(f"Password reset event: {etype}")

        if sev in ("WARN", "ERROR"):
            high_severity += 1

    risk_level = "low"

    if failed_auth >= 5 or high_severity >= 3:
        risk_level = "medium"
        reasons.append(
            "Multiple failed authentication attempts or high-severity events detected."
        )

    if password_resets >= 1 and failed_auth >= 3:
        risk_level = "high"
        reasons.append(
            "Password reset occurred along with multiple authentication failures in a short period."
        )

    if password_resets >= 2 or (failed_auth >= 10 and high_severity >= 5):
        risk_level = "critical"
        reasons.append(
            "Strong indication of account takeover or an aggressive attack pattern."
        )

    if not reasons:
        reasons.append(
            "No strong anomaly detected in the given time range based on simple heuristics."
        )

    recommended_actions: List[Dict[str, Any]] = []
    notify: List[Dict[str, Any]] = []

    if risk_level == "low":
        recommended_actions.append(
            {"action": "monitor_only", "reason": "No strong risk signals detected."}
        )
    elif risk_level == "medium":
        recommended_actions.append(
            {
                "action": "monitor_and_review_logs",
                "reason": "Some anomalies detected. Manual review is recommended.",
            }
        )
    elif risk_level == "high":
        recommended_actions.append(
            {
                "action": "force_password_reset",
                "reason": "Signs of possible account compromise.",
            }
        )
        recommended_actions.append(
            {
                "action": "terminate_active_sessions",
                "reason": "Terminate active sessions to contain potential access.",
            }
        )
        notify.append(
            {
                "role": "security_team",
                "reason": "High-risk activity detected for this user.",
            }
        )
    elif risk_level == "critical":
        recommended_actions.append(
            {
                "action": "suspend_user",
                "reason": "Strong signals of account takeover.",
            }
        )
        recommended_actions.append(
            {
                "action": "terminate_active_sessions",
                "reason": "Immediate containment is required.",
            }
        )
        notify.append(
            {
                "role": "security_team",
                "reason": "Critical incident. Immediate investigation is required.",
            }
        )

    behavior_summary = (
        f"Analyzed {len(semantic_events)} events for user '{user_login}' "
        f"in the last {time_range_hours} hours: "
        f"{failed_auth} auth failures, {mfa_events} MFA events, "
        f"{password_resets} password reset events, {high_severity} high-severity events."
    )

    return {
        "risk_level": risk_level,
        "behavior_summary": behavior_summary,
        "risk_reasons": reasons,
        "recommended_actions": recommended_actions,
        "notify": notify,
    }


# ============================================================
# D: Embeddings + local JSONL vector store
# ============================================================


def get_vector_db_path() -> str:
    """
    Return the path to the JSONL file used as a simple vector store.
    """
    return os.getenv("VECTOR_DB_PATH", "./vector_db.jsonl")


def embed_text(text: str) -> List[float]:
    """
    Generate an embedding for the given text using OpenAI.
    """
    client = get_openai_client()
    resp = client.embeddings.create(
        model="text-embedding-3-small",
        input=text,
    )
    return resp.data[0].embedding  # type: ignore[attr-defined]


def cosine_similarity(v1: List[float], v2: List[float]) -> float:
    """
    Compute cosine similarity between two embedding vectors.
    """
    if not v1 or not v2 or len(v1) != len(v2):
        return 0.0
    dot = 0.0
    n1 = 0.0
    n2 = 0.0
    for a, b in zip(v1, v2):
        dot += a * b
        n1 += a * a
        n2 += b * b
    if n1 == 0 or n2 == 0:
        return 0.0
    return dot / (math.sqrt(n1) * math.sqrt(n2))


def load_vector_index() -> List[Dict[str, Any]]:
    """
    Load all records from the local JSONL vector store.
    """
    path = get_vector_db_path()
    if not os.path.exists(path):
        return []

    records: List[Dict[str, Any]] = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
                records.append(rec)
            except Exception:
                continue
    return records


def append_vector_record(record: Dict[str, Any]) -> None:
    """
    Append a single record (including embedding) to the JSONL vector store.
    """
    path = get_vector_db_path()
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")


def build_behavior_text(
    semantic_events: List[Dict[str, Any]],
    limit: int = 20,
) -> str:
    """
    Convert semantic events into compact text lines for embedding.

    Only the latest 'limit' events are used to keep the text manageable.
    """
    subset = semantic_events[-limit:]
    lines: List[str] = []
    for ev in subset:
        t = ev.get("event_time") or ""
        etype = ev.get("event_type") or ""
        cat = ev.get("category") or ""
        sev = ev.get("severity") or ""
        out = ev.get("outcome") or {}
        result = out.get("result") or ""
        user_login = (ev.get("subject_user") or {}).get("login") or ""
        ip = (ev.get("client") or {}).get("ip") or ""
        line = (
            f"time={t} event={etype} category={cat} severity={sev} result={result} "
            f"user={user_login} ip={ip}"
        )
        lines.append(line)
    return "\n".join(lines)


def index_current_behavior(
    user_login: str,
    time_range_hours: int,
    risk_result: Dict[str, Any],
    semantic_events: List[Dict[str, Any]],
) -> Tuple[str, List[float]]:
    """
    Store the current behavior summary and events as a single vector record.

    Returns:
        (record_id, embedding)
    """
    text = risk_result["behavior_summary"] + "\n" + build_behavior_text(semantic_events)
    embedding = embed_text(text)
    record_id = str(uuid.uuid4())
    record = {
        "id": record_id,
        "user": user_login,
        "time_range_hours": time_range_hours,
        "risk_level": risk_result["risk_level"],
        "behavior_summary": risk_result["behavior_summary"],
        "text": text,
        "embedding": embedding,
    }
    append_vector_record(record)
    return record_id, embedding


def find_similar_behaviors(
    query_embedding: List[float],
    top_k: int = 3,
    exclude_id: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """
    Search the local JSONL vector store for behaviors similar to the given vector.
    """
    records = load_vector_index()
    scored: List[Tuple[float, Dict[str, Any]]] = []

    for rec in records:
        if exclude_id and rec.get("id") == exclude_id:
            continue
        emb = rec.get("embedding")
        if not emb:
            continue
        sim = cosine_similarity(query_embedding, emb)
        scored.append((sim, rec))

    scored.sort(key=lambda x: x[0], reverse=True)
    top = scored[:top_k]

    results: List[Dict[str, Any]] = []
    for sim, rec in top:
        results.append(
            {
                "id": rec.get("id"),
                "user": rec.get("user"),
                "risk_level": rec.get("risk_level"),
                "similarity": sim,
                "behavior_summary": rec.get("behavior_summary"),
            }
        )
    return results


# ============================================================
# Okta Workflows integration for System Log retrieval
# ============================================================


def fetch_logs_via_workflows(
    user_login: str,
    time_range_hours: int,
    reason: str,
) -> Dict[str, Any]:
    """
    Call the Okta Workflows HTTP endpoint (search_logs flow)
    to retrieve System Logs.
    """
    url = os.getenv("OKTA_WF_SEARCH_LOGS_URL")
    token = os.getenv("OKTA_WF_SEARCH_LOGS_TOKEN")

    if not url or not token:
        raise RuntimeError("OKTA_WF_SEARCH_LOGS_URL / OKTA_WF_SEARCH_LOGS_TOKEN not configured")

    headers = {
        "Authorization": f"SSWS {token}",
        "Content-Type": "application/json",
    }
    payload = {
        "user_login": user_login,
        "time_range_hours": time_range_hours,
        "reason": reason or "AI analyze_identity_state",
    }

    resp = requests.post(url, headers=headers, json=payload, timeout=30)
    resp.raise_for_status()
    return resp.json()


def extract_system_logs_from_workflows_response(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Normalize various Workflows response shapes into a list of log entries.

    Typical example:
        { "System Logs": [ {...}, {...} ] }

    Falls back to common keys like "system_logs", "logs", "items".
    """
    if not isinstance(data, dict):
        return []

    if "System Logs" in data and isinstance(data["System Logs"], list):
        return data["System Logs"]

    for key in ["system_logs", "logs", "items"]:
        if key in data and isinstance(data[key], list):
            return data[key]

    return []


# ============================================================
# Public MCP tool: analyze_identity_state
# ============================================================


@mcp.tool
def analyze_identity_state(
    user: str,
    time_range_hours: int = 24,
    reason: str = "",
) -> Dict[str, Any]:
    """
    Analyze the recent IAM state of a user, and index the behavior as a vector.

    Internal steps:
        1. Call an Okta Workflows search_logs flow to retrieve System Logs.
        2. Normalize Okta System Logs into the semantic event schema.
        3. Run heuristic risk analysis.
        4. Generate an embedding from the behavior summary and events, then
           store it in a local JSONL vector store.
        5. Search for similar past behaviors and return them as vector_context.

    Clients (Claude / ChatGPT / other MCP clients) only need to provide:
        - `user` (login identifier)
        - `time_range_hours`

    They do not need to know the semantic schema or vector store structure.
    """
    try:
        logs_raw = fetch_logs_via_workflows(
            user_login=user,
            time_range_hours=time_range_hours,
            reason=reason,
        )
    except Exception as exc:
        logger.exception("Failed to fetch logs via Workflows")
        return {
            "status": "error",
            "error": "failed_to_fetch_logs",
            "message": str(exc),
        }

    system_logs = extract_system_logs_from_workflows_response(logs_raw)

    semantic_events: List[Dict[str, Any]] = []
    for entry in system_logs:
        try:
            semantic_events.append(normalize_okta_event(entry))
        except Exception as exc:
            logger.exception("Failed to normalize event")
            semantic_events.append(
                {
                    "version": SEMANTIC_EVENT_VERSION,
                    "event_id": None,
                    "event_time": None,
                    "event_type": None,
                    "category": "parse_error",
                    "action": None,
                    "display_message": f"Failed to normalize event: {str(exc)}",
                    "severity": "ERROR",
                    "actor": None,
                    "primary_target": None,
                    "subject_user": None,
                    "client": None,
                    "request": None,
                    "outcome": None,
                }
            )

    risk_result = analyze_risk(
        semantic_events,
        user_login=user,
        time_range_hours=time_range_hours,
    )

    vector_context: Dict[str, Any] = {
        "indexed": False,
        "index_id": None,
        "similar_behaviors": [],
    }

    try:
        current_id, current_embedding = index_current_behavior(
            user_login=user,
            time_range_hours=time_range_hours,
            risk_result=risk_result,
            semantic_events=semantic_events,
        )
        similar = find_similar_behaviors(
            query_embedding=current_embedding,
            top_k=3,
            exclude_id=current_id,
        )
        vector_context = {
            "indexed": True,
            "index_id": current_id,
            "similar_behaviors": similar,
        }
    except Exception as exc:
        logger.exception("Vector indexing/search failed")
        vector_context = {
            "indexed": False,
            "error": str(exc),
            "similar_behaviors": [],
        }

    return {
        "status": "success",
        "user": user,
        "time_range_hours": time_range_hours,
        "risk_level": risk_result["risk_level"],
        "behavior_summary": risk_result["behavior_summary"],
        "risk_reasons": risk_result["risk_reasons"],
        "recommended_actions": risk_result["recommended_actions"],
        "notify": risk_result["notify"],
        "event_count": len(semantic_events),
        "events": semantic_events,
        "vector_context": vector_context,
    }


if __name__ == "__main__":
    mcp.run()
