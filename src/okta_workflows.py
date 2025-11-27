"""
FastMCP Okta Workflows Integration - Consolidated Implementation

Key characteristics:
1. Unified collection and analysis of log data (with response-size optimization).
2. Device Authorization Grant support (scope must always be included in the request body).
3. Support for multiple Okta implementations and HTTP 400 handling.
4. Detailed logging of requests and responses.
5. Enhanced error handling, including scope and token validation.
6. Stateless design suitable for FastMCP Cloud (no server-side device session storage).

All tokens and URLs are provided via environment variables; there are no
hard-coded secrets in this file.
"""

import os
import json
import logging
from datetime import datetime
from math import radians, cos, sin, asin, sqrt
from typing import List, Dict, Any, Optional

import base64  # kept because it may be useful for future extensions
import jwt
import numpy as np
import requests
from jwt.algorithms import RSAAlgorithm
from sklearn.ensemble import IsolationForest
from fastmcp import FastMCP

# ===== Logging configuration =====
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

# ===== FastMCP server =====
mcp = FastMCP("Okta Workflows")

# ===== OAuth configuration =====
OAUTH_CONFIG: Dict[str, Optional[str]] = {
    "issuer": (os.getenv("OKTA_ISSUER") or "").rstrip("/") or None,
    "client_id": os.getenv("OKTA_CLIENT_ID"),
    "client_secret": os.getenv("OKTA_CLIENT_SECRET"),
    "auth_server_id": os.getenv("OKTA_AUTH_SERVER_ID"),
}

issuer = OAUTH_CONFIG.get("issuer")
auth_server_id = OAUTH_CONFIG.get("auth_server_id")
if issuer and auth_server_id:
    OAUTH_CONFIG.update(
        {
            "device_auth_endpoint": f"{issuer}/v1/device/authorize",
            "token_endpoint": f"{issuer}/v1/token",
            "jwks_uri": f"{issuer}/v1/keys",
        }
    )
else:
    # These will be validated later in validate_config()
    OAUTH_CONFIG.update(
        {
            "device_auth_endpoint": None,
            "token_endpoint": None,
            "jwks_uri": None,
        }
    )

logger.info("Okta OAuth configuration initialized")

# ===== Stateless cache and global state =====
# FastMCP Cloud does not guarantee process-level state persistence.
# We therefore avoid storing device sessions on the server.
jwks_cache: Optional[Dict[str, Any]] = None
jwks_cache_time: Optional[datetime] = None

# Simple in-memory cache for IP geolocation lookups
ip_geo_cache: Dict[str, Dict[str, Any]] = {}

# Minimum number of samples required for ML anomaly detection
MIN_SAMPLES_FOR_ML = 20

# ===== Okta Workflows configuration =====
WORKFLOWS_CONFIG: Dict[str, Dict[str, Optional[str]]] = {
    "reset_password": {
        "url": os.getenv("OKTA_WF_RESET_PASSWORD_URL"),
        "token": os.getenv("OKTA_WF_RESET_PASSWORD_TOKEN"),
    },
    "suspend_user": {
        "url": os.getenv("OKTA_WF_SUSPEND_USER_URL"),
        "token": os.getenv("OKTA_WF_SUSPEND_USER_TOKEN"),
    },
    "search_logs": {
        "url": os.getenv("OKTA_WF_SEARCH_LOGS_URL"),
        "token": os.getenv("OKTA_WF_SEARCH_LOGS_TOKEN"),
    },
    "read_user": {
        "url": os.getenv("OKTA_WF_READ_USER_URL"),
        "token": os.getenv("OKTA_WF_READ_USER_TOKEN"),
    },
    "notify_user": {
        "url": os.getenv("OKTA_WF_NOTIFY_USER_URL"),
        "token": os.getenv("OKTA_WF_NOTIFY_USER_TOKEN"),
    },
}

# ===== Scope definitions =====
TOOL_SCOPES: Dict[str, List[str]] = {
    "search_logs": ["mcp:logs:read"],
    "read_user": ["mcp:user:read:basic", "mcp:user:read:full"],
    "detect_anomalies_ml": ["mcp:analyze:ml"],
    "detect_impossible_travel": ["mcp:analyze:ml"],
    "analyze_user_with_external_context": [
        "mcp:analyze:ml",
        "mcp:logs:read",
        "mcp:user:read:full",
    ],
    "reset_password": ["mcp:user:write"],
    "suspend_user": ["mcp:user:write"],
}

# Whether each tool requires ALL scopes (AND) or ANY of them
TOOL_SCOPE_MATCH_MODE: Dict[str, bool] = {
    # True: all listed scopes are required (AND)
    # False: any one of the listed scopes suffices (ANY)
    "search_logs": True,
    "read_user": True,
    "detect_anomalies_ml": True,
    "detect_impossible_travel": True,
    "analyze_user_with_external_context": True,
    "reset_password": True,
    "suspend_user": True,
}

# ===== Utility functions =====


def validate_config() -> bool:
    """
    Validate that the core OAuth configuration is present.
    """
    required = [
        "issuer",
        "client_id",
        "client_secret",
        "auth_server_id",
        "device_auth_endpoint",
        "token_endpoint",
        "jwks_uri",
    ]
    for key in required:
        if not OAUTH_CONFIG.get(key):
            logger.error("Missing OAuth configuration: %s", key)
            return False
    logger.info("OAuth configuration validated")
    return True


def authorization_required_error(tool_key: str, display_name: Optional[str] = None) -> Dict[str, Any]:
    """
    Build a standardized error response indicating that authorization is required.

    Parameters:
        tool_key:
            Internal tool name (e.g. 'search_logs', 'reset_password').
        display_name:
            Optional human-readable name for the tool.
    """
    if display_name is None:
        display_name = tool_key

    return {
        "status": "error",
        "error": "authorization_required",
        "message": (
            "Authorization is required to use this tool.\n\n"
            f"Tool: {display_name}\n\n"
            "Please perform the following steps:\n"
            "1. Call initiate_device_auth() with the tools you want to use.\n"
            "2. Visit the verification URL and approve access in Okta.\n"
            "3. Call complete_device_auth() with the returned device_code to obtain an access token."
        ),
        "required_scopes": TOOL_SCOPES.get(tool_key, []),
        "next_action": "initiate_device_auth()",
    }


def get_jwks() -> Optional[Dict[str, Any]]:
    """
    Retrieve Okta JWKS (public keys) with basic caching.
    """
    global jwks_cache, jwks_cache_time

    now = datetime.now()
    if jwks_cache and jwks_cache_time and (now - jwks_cache_time).total_seconds() < 3600:
        logger.debug("JWKS retrieved from cache")
        return jwks_cache

    try:
        if not OAUTH_CONFIG.get("jwks_uri"):
            logger.error("JWKS URI is not configured")
            return None

        logger.debug("Fetching JWKS from: %s", OAUTH_CONFIG["jwks_uri"])
        response = requests.get(OAUTH_CONFIG["jwks_uri"], timeout=10)
        response.raise_for_status()
        jwks_cache = response.json()
        jwks_cache_time = now
        logger.info("JWKS fetched: %d keys", len(jwks_cache.get("keys", [])))
        return jwks_cache
    except Exception as exc:
        logger.error("Failed to retrieve JWKS: %s", str(exc))
        return None


def verify_access_token(access_token: str) -> Dict[str, Any]:
    """
    Verify an Access Token using Okta JWKS and extract its scopes.

    Returns:
        {
          "status": "success" or "error",
          "user_id": "<sub>",
          "scopes": [...],
          "claims": {...},
          "error": "<message>"         # only on error
        }
    """
    try:
        if not access_token or not isinstance(access_token, str):
            return {"status": "error", "error": "Invalid token format"}

        header = jwt.get_unverified_header(access_token)
        kid = header.get("kid")

        if not kid:
            logger.error("No 'kid' in JWT header")
            return {"status": "error", "error": "No 'kid' in JWT header"}

        jwks = get_jwks()
        if not jwks:
            return {"status": "error", "error": "Failed to retrieve JWKS"}

        jwk_key = None
        for key in jwks.get("keys", []):
            if key.get("kid") == kid:
                jwk_key = key
                break

        if not jwk_key:
            logger.error("Public key not found for kid: %s", kid)
            return {"status": "error", "error": "Public key not found"}

        try:
            public_key = RSAAlgorithm.from_jwk(json.dumps(jwk_key))
        except Exception as exc:
            logger.error("Failed to convert JWK: %s", str(exc))
            return {"status": "error", "error": "Failed to convert JWK"}

        try:
            decoded = jwt.decode(
                access_token,
                public_key,
                algorithms=["RS256"],
                audience=["api://mcp"],
                issuer=OAUTH_CONFIG["issuer"],
            )
            logger.info("Token verified for subject: %s", decoded.get("sub"))
        except jwt.ExpiredSignatureError:
            logger.warning("Token expired")
            return {"status": "error", "error": "Token expired"}
        except jwt.InvalidTokenError as exc:
            logger.error("Invalid token: %s", str(exc))
            return {"status": "error", "error": str(exc)}

        raw_scope = decoded.get("scp") or decoded.get("scope")
        if isinstance(raw_scope, str):
            scopes = raw_scope.split()
        elif isinstance(raw_scope, list):
            scopes = raw_scope
        else:
            scopes = []

        return {
            "status": "success",
            "user_id": decoded.get("sub"),
            "scopes": scopes,
            "claims": decoded,
        }

    except Exception as exc:
        logger.error("Token verification error: %s", str(exc))
        return {"status": "error", "error": str(exc)}


def check_scope(access_token: str, required_scopes: List[str], tool_key: str) -> Dict[str, Any]:
    """
    Check whether the token satisfies the required scopes for a tool.

    Honors TOOL_SCOPE_MATCH_MODE[tool_key] to decide AND vs ANY logic.
    """
    token_info = verify_access_token(access_token)
    if token_info.get("status") != "success":
        return token_info

    token_scopes = token_info.get("scopes", [])
    if not required_scopes:
        logger.debug("No required scopes configured; skipping scope check")
        return token_info

    mode_and = TOOL_SCOPE_MATCH_MODE.get(tool_key, True)

    if mode_and:
        has_required_scope = all(scope in token_scopes for scope in required_scopes)
    else:
        has_required_scope = any(scope in token_scopes for scope in required_scopes)

    if not has_required_scope:
        logger.warning(
            "Insufficient scopes for %s. Required=%s, Actual=%s",
            tool_key,
            required_scopes,
            token_scopes,
        )
        return {
            "status": "error",
            "error": f"Insufficient scope. Required: {required_scopes}",
        }

    logger.debug("Scope check passed for %s", tool_key)
    return token_info


def call_okta_workflow(workflow_name: str, user_login: str, reason: str) -> Dict[str, Any]:
    """
    Call an Okta Workflows HTTP flow with the standard payload
    (user_login + reason).
    """
    try:
        if workflow_name not in WORKFLOWS_CONFIG:
            logger.error("Workflow '%s' not configured", workflow_name)
            return {
                "status": "error",
                "error": f"Workflow '{workflow_name}' not configured",
            }

        config = WORKFLOWS_CONFIG[workflow_name]
        if not config.get("url") or not config.get("token"):
            logger.error("Workflow '%s' missing URL or token", workflow_name)
            return {
                "status": "error",
                "error": "Workflow not properly configured",
            }

        headers = {
            "Authorization": f"SSWS {config['token']}",
            "Content-Type": "application/json",
        }
        payload = {"user_login": user_login, "reason": reason}

        logger.debug("Calling workflow: %s", workflow_name)
        response = requests.post(
            config["url"],
            json=payload,
            headers=headers,
            timeout=30,
        )
        logger.debug(
            "Workflow response status=%s, body=%s",
            response.status_code,
            response.text[:500],
        )
        response.raise_for_status()

        logger.info("Workflow %s executed successfully", workflow_name)
        return {"status": "success", "result": response.json()}
    except Exception as exc:
        logger.error("Failed to call workflow '%s': %s", workflow_name, str(exc))
        return {"status": "error", "error": str(exc)}


def call_okta_workflow_generic(workflow_name: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    Call an Okta Workflows HTTP flow with an arbitrary JSON payload.

    Used, for example, for notification flows.
    """
    try:
        if workflow_name not in WORKFLOWS_CONFIG:
            return {
                "status": "error",
                "error": f"Workflow '{workflow_name}' not configured",
            }

        config = WORKFLOWS_CONFIG[workflow_name]
        if not config.get("url") or not config.get("token"):
            return {
                "status": "error",
                "error": "Workflow not properly configured",
            }

        headers = {
            "Authorization": f"SSWS {config['token']}",
            "Content-Type": "application/json",
        }

        response = requests.post(
            config["url"],
            json=payload,
            headers=headers,
            timeout=30,
        )
        response.raise_for_status()
        return {"status": "success", "result": response.json()}
    except Exception as exc:
        return {"status": "error", "error": str(exc)}


def calculate_distance(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """
    Calculate distance (km) between two coordinates using the Haversine formula.
    """
    try:
        lon1, lat1, lon2, lat2 = map(radians, [lon1, lat1, lon2, lat2])
        dlon = lon2 - lon1
        dlat = lat2 - lat1
        a = sin(dlat / 2) ** 2 + cos(lat1) * cos(lat2) * sin(dlon / 2) ** 2
        c = 2 * asin(sqrt(a))
        return c * 6371
    except Exception as exc:
        logger.error("Error calculating distance: %s", str(exc))
        return 0.0


def calculate_time_diff(time1_str: str, time2_str: str) -> float:
    """
    Calculate the time difference (minutes) between two ISO timestamps.
    """
    try:
        dt1 = datetime.fromisoformat(time1_str.replace("Z", "+00:00"))
        dt2 = datetime.fromisoformat(time2_str.replace("Z", "+00:00"))
        diff = abs((dt2 - dt1).total_seconds() / 60)
        return max(diff, 1.0)
    except Exception:
        return 1.0


def get_geo_for_ip(ip_address: str) -> Optional[Dict[str, Any]]:
    """
    Resolve IP geolocation via ip-api.com with basic caching.
    """
    if not ip_address:
        return None

    if ip_address in ip_geo_cache:
        return ip_geo_cache[ip_address]

    try:
        res = requests.get(
            f"http://ip-api.com/json/{ip_address}",
            timeout=5,
        )
        data = res.json()
        if data.get("status") == "success":
            ip_geo_cache[ip_address] = data
            return data
        return None
    except Exception as exc:
        logger.debug("Geo lookup failed for %s: %s", ip_address, str(exc))
        return None


# ===== Log analysis functions =====


def extract_and_analyze_logs(logs: Dict[str, Any]) -> Dict[str, Any]:
    """
    Perform combined ML-based anomaly detection and impossible travel detection
    over a System Logs payload from Okta Workflows.

    Returns:
        {
            "total_logs": int,
            "anomaly_analysis": {...},
            "travel_analysis": {...},
        }
    """
    result: Dict[str, Any] = {
        "total_logs": 0,
        "anomaly_analysis": {
            "mean_anomaly_score": 0.0,
            "anomaly_count": 0,
            "anomaly_percentage": 0.0,
            "is_anomalous": False,
            "failed_login_events": 0,
            "mfa_events": 0,
        },
        "travel_analysis": {
            "total_logins": 0,
            "suspicious_travels": [],
            "is_suspicious": False,
        },
    }

    try:
        if not isinstance(logs, dict):
            return result

        system_logs = logs.get("System Logs", [])
        if not isinstance(system_logs, list):
            return result

        result["total_logs"] = len(system_logs)
        logger.info("Processing %d logs", len(system_logs))

        # 1. ML anomaly detection features
        features: List[Dict[str, Any]] = []
        failed_count = 0
        mfa_count = 0

        for log in system_logs:
            if not log or not isinstance(log, dict):
                continue

            published = log.get("Published", "")
            try:
                dt = datetime.fromisoformat(published.replace("Z", "+00:00"))
                hour_of_day = dt.hour
                day_of_week = dt.weekday()
            except Exception:
                hour_of_day = 12
                day_of_week = 0

            event_type = log.get("Event Type", "") or ""
            has_mfa = 1 if ("mfa" in event_type.lower() or "factor" in event_type.lower()) else 0
            if has_mfa:
                mfa_count += 1

            display_msg = (log.get("Display Message") or "").lower()
            is_failed = 1 if ("fail" in display_msg or "error" in display_msg) else 0
            if is_failed:
                failed_count += 1

            severity = log.get("Severity", "") or ""
            severity_score = 2 if severity == "WARN" else (3 if severity == "ERROR" else 0)

            feat = {
                "hour_of_day": hour_of_day,
                "day_of_week": day_of_week,
                "is_failed": is_failed,
                "has_mfa": has_mfa,
                "severity_score": severity_score,
            }
            features.append(feat)

        if features and len(features) >= MIN_SAMPLES_FOR_ML:
            X = np.array([list(f.values()) for f in features])
            model = IsolationForest(contamination=0.1, random_state=42)
            model.fit(X)

            anomaly_scores = model.decision_function(X)
            predictions = model.predict(X)

            mean_anomaly_score = float(np.mean(anomaly_scores))
            anomaly_count = int(np.sum(predictions == -1))

            result["anomaly_analysis"] = {
                "mean_anomaly_score": mean_anomaly_score,
                "anomaly_count": anomaly_count,
                "anomaly_percentage": round((anomaly_count / len(features)) * 100, 2),
                "is_anomalous": mean_anomaly_score < -0.3,
                "failed_login_events": failed_count,
                "mfa_events": mfa_count,
            }
            logger.debug(
                "ML analysis: score=%s, count=%s, features=%s",
                mean_anomaly_score,
                anomaly_count,
                len(features),
            )
        else:
            logger.info(
                "Skipping ML analysis due to insufficient samples (got %d, need %d)",
                len(features),
                MIN_SAMPLES_FOR_ML,
            )
            result["anomaly_analysis"]["failed_login_events"] = failed_count
            result["anomaly_analysis"]["mfa_events"] = mfa_count

        # 2. Impossible travel detection
        logins: List[Dict[str, Any]] = []
        for log in system_logs:
            client = log.get("Client", {}) or {}
            ip_address = client.get("ipAddress")
            published = log.get("Published")
            if ip_address and published:
                logins.append({"ip": ip_address, "time": published})

        result["travel_analysis"]["total_logins"] = len(logins)

        if len(logins) >= 2:
            suspicious: List[Dict[str, Any]] = []
            for i in range(len(logins) - 1):
                current = logins[i]
                next_login = logins[i + 1]

                try:
                    geo_current = get_geo_for_ip(current["ip"])
                    geo_next = get_geo_for_ip(next_login["ip"])

                    if not geo_current or not geo_next:
                        continue

                    distance = calculate_distance(
                        geo_current["lat"],
                        geo_current["lon"],
                        geo_next["lat"],
                        geo_next["lon"],
                    )

                    time_diff_minutes = calculate_time_diff(
                        current["time"],
                        next_login["time"],
                    )

                    if time_diff_minutes == 0:
                        continue

                    speed_kmh = (distance / time_diff_minutes) * 60.0

                    # Above typical commercial aircraft cruising speed is treated as "impossible".
                    if speed_kmh > 900:
                        suspicious.append(
                            {
                                "from": f"{geo_current.get('city', 'Unknown')}, "
                                f"{geo_current.get('country', 'Unknown')}",
                                "to": f"{geo_next.get('city', 'Unknown')}, "
                                f"{geo_next.get('country', 'Unknown')}",
                                "distance_km": round(distance, 2),
                                "time_minutes": round(time_diff_minutes, 2),
                                "required_speed_kmh": round(speed_kmh, 2),
                            }
                        )
                except Exception as exc:
                    logger.debug("Error analyzing travel: %s", str(exc))
                    continue

            result["travel_analysis"]["suspicious_travels"] = suspicious
            result["travel_analysis"]["is_suspicious"] = len(suspicious) > 0
            logger.debug(
                "Travel analysis: %d suspicious travels",
                len(suspicious),
            )

        return result

    except Exception as exc:
        logger.error("Error in extract_and_analyze_logs: %s", str(exc))
        return result


# ===== MCP tools =====


@mcp.tool
def initiate_device_auth(tools: Optional[List[str]] = None) -> Dict[str, Any]:
    """
    Start a Device Authorization flow.

    The scope is derived from the union of scopes required by the requested tools.
    The client must then guide the user to the verification URL and later call
    complete_device_auth(device_code=...).
    """
    try:
        if not validate_config():
            return {
                "status": "error",
                "error": "Configuration error",
                "message": "Okta OAuth configuration is incomplete.",
            }

        required_scopes: set[str] = set()
        if tools and isinstance(tools, list) and tools:
            logger.info("Tool-specific scopes requested: %s", tools)
            for tool in tools:
                if tool in TOOL_SCOPES:
                    required_scopes.update(TOOL_SCOPES[tool])

        if not required_scopes:
            logger.info("No tools specified; using union of all tool scopes.")
            for scopes in TOOL_SCOPES.values():
                required_scopes.update(scopes)

        scope_string = " ".join(sorted(required_scopes))
        logger.info("Final scope set (%d): %s", len(required_scopes), scope_string)

        auth = (OAUTH_CONFIG["client_id"], OAUTH_CONFIG["client_secret"])
        request_data = {"scope": scope_string}

        logger.info("Device Auth Endpoint: %s", OAUTH_CONFIG["device_auth_endpoint"])
        logger.debug("Device auth request body: %s", request_data)

        response = requests.post(
            OAUTH_CONFIG["device_auth_endpoint"],
            auth=auth,
            data=request_data,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=10,
        )

        logger.debug(
            "Device auth response status=%s, body=%s",
            response.status_code,
            response.text[:500],
        )

        if response.status_code == 200:
            device_response = response.json()
            device_code = device_response.get("device_code")

            logger.info("Device Authorization initiated successfully")

            expires_in = device_response.get("expires_in", 600)

            # Device state is not stored server-side; the client must retain device_code.
            return {
                "status": "success",
                "device_code": device_code,
                "user_code": device_response.get("user_code"),
                "verification_uri": device_response.get("verification_uri_complete"),
                "expires_in": expires_in,
                "scopes": sorted(list(required_scopes)),
                "message": (
                    "Device Authorization Started\n\n"
                    f"User Code: {device_response.get('user_code')}\n\n"
                    f"Visit: {device_response.get('verification_uri_complete')}\n\n"
                    f"Then call: complete_device_auth(device_code='{device_code}')"
                ),
            }

        logger.error(
            "HTTP %s from device authorize endpoint: %s",
            response.status_code,
            response.text[:500],
        )

        error_code = None
        error_description = None
        details: Any = None
        try:
            payload = response.json()
            error_code = payload.get("error")
            error_description = payload.get("error_description")
            details = payload
        except Exception:
            details = response.text[:500]

        return {
            "status": "error",
            "error": f"HTTP {response.status_code}",
            "error_code": error_code,
            "error_description": error_description,
            "http_status": response.status_code,
            "details": details,
            "endpoint": OAUTH_CONFIG["device_auth_endpoint"],
            "auth_server_id": OAUTH_CONFIG["auth_server_id"],
            "scope_count": len(required_scopes),
        }

    except Exception as exc:
        logger.error("Exception in initiate_device_auth: %s", str(exc))
        logger.exception(exc)
        return {"status": "error", "error": str(exc)}


@mcp.tool
def complete_device_auth(device_code: str) -> Dict[str, Any]:
    """
    Exchange a device_code for an access token.

    The device_code must be the same value returned by initiate_device_auth().
    """
    try:
        if not validate_config():
            return {
                "status": "error",
                "error": "Configuration error",
                "message": "Okta OAuth configuration is incomplete.",
            }

        if not device_code:
            logger.error("Device code is empty")
            return {
                "status": "error",
                "error": "Device code is required",
            }

        auth = (OAUTH_CONFIG["client_id"], OAUTH_CONFIG["client_secret"])
        data = {
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
            "device_code": device_code,
        }

        logger.debug("Exchanging device code for access token")
        response = requests.post(
            OAUTH_CONFIG["token_endpoint"],
            auth=auth,
            data=data,
            timeout=10,
        )

        logger.debug(
            "Token endpoint response status=%s, body=%s",
            response.status_code,
            response.text[:500],
        )

        if response.status_code != 200:
            error_code = None
            error_description = None
            details: Any = None
            try:
                payload = response.json()
                error_code = payload.get("error")
                error_description = payload.get("error_description")
                details = payload
            except Exception:
                details = response.text[:500]

            logger.error(
                "Token endpoint returned error: status=%s, error=%s, description=%s",
                response.status_code,
                error_code,
                error_description,
            )

            return {
                "status": "error",
                "error": "token_endpoint_error",
                "http_status": response.status_code,
                "error_code": error_code,
                "error_description": error_description,
                "details": details,
            }

        token_response = response.json()
        access_token = token_response.get("access_token")

        if not access_token:
            logger.error("No access token in token endpoint response")
            return {"status": "error", "error": "No access token in response"}

        token_info = verify_access_token(access_token)
        if token_info.get("status") != "success":
            logger.error("Token verification failed after exchange")
            return token_info

        logger.info("Token exchange and verification succeeded")

        return {
            "status": "success",
            "access_token": access_token,
            "user_id": token_info.get("user_id"),
            "scopes": token_info.get("scopes", []),
            "token_type": "Bearer",
        }

    except Exception as exc:
        logger.error("Token exchange error: %s", str(exc))
        logger.exception(exc)
        return {"status": "error", "error": str(exc)}


@mcp.tool
def search_logs(user_login: str, reason: str, access_token: Optional[str] = None) -> Dict[str, Any]:
    """
    Search and analyze System Logs for a given user.

    Performs both ML-based anomaly detection and impossible travel detection.
    """
    if not access_token:
        return authorization_required_error("search_logs", "Log search")

    scope_check = check_scope(
        access_token,
        TOOL_SCOPES.get("search_logs", []),
        tool_key="search_logs",
    )
    if scope_check.get("status") != "success":
        return scope_check

    logger.info("Searching logs for: %s", user_login)

    logs_response = call_okta_workflow("search_logs", user_login, reason)
    if logs_response.get("status") != "success":
        logger.error("Failed to retrieve logs")
        return {"status": "error", "error": "Failed to retrieve logs"}

    logs_data = logs_response.get("result", {})
    analysis_result = extract_and_analyze_logs(logs_data)

    return {
        "status": "success",
        "user": user_login,
        "total_logs": analysis_result["total_logs"],
        "anomaly_analysis": analysis_result["anomaly_analysis"],
        "travel_analysis": analysis_result["travel_analysis"],
    }


@mcp.tool
def detect_anomalies_ml(user_login: str, reason: str, access_token: Optional[str] = None) -> Dict[str, Any]:
    """
    Run ML-based anomaly detection on System Logs for a given user.
    """
    if not access_token:
        return authorization_required_error("detect_anomalies_ml", "ML anomaly detection")

    scope_check = check_scope(
        access_token,
        TOOL_SCOPES.get("detect_anomalies_ml", []),
        tool_key="detect_anomalies_ml",
    )
    if scope_check.get("status") != "success":
        return scope_check

    logger.info("ML anomaly detection for: %s", user_login)

    logs_response = call_okta_workflow("search_logs", user_login, reason)
    if logs_response.get("status") != "success":
        logger.error("Failed to retrieve logs")
        return {"status": "error", "error": "Failed to retrieve logs"}

    logs_data = logs_response.get("result", {})
    analysis_result = extract_and_analyze_logs(logs_data)

    return {
        "status": "success",
        "user": user_login,
        "total_logs_analyzed": analysis_result["total_logs"],
        "anomaly_analysis": analysis_result["anomaly_analysis"],
    }


@mcp.tool
def detect_impossible_travel(
    user_login: str,
    reason: str,
    access_token: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Detect impossible travel patterns for a given user.
    """
    if not access_token:
        return authorization_required_error("detect_impossible_travel", "Impossible travel detection")

    scope_check = check_scope(
        access_token,
        TOOL_SCOPES.get("detect_impossible_travel", []),
        tool_key="detect_impossible_travel",
    )
    if scope_check.get("status") != "success":
        return scope_check

    logger.info("Impossible travel detection for: %s", user_login)

    logs_response = call_okta_workflow("search_logs", user_login, reason)
    if logs_response.get("status") != "success":
        logger.error("Failed to retrieve logs")
        return {"status": "error", "error": "Failed to retrieve logs"}

    logs_data = logs_response.get("result", {})
    analysis_result = extract_and_analyze_logs(logs_data)

    return {
        "status": "success",
        "user": user_login,
        "travel_analysis": analysis_result["travel_analysis"],
    }


@mcp.tool
def read_user(user_login: str, reason: str, access_token: Optional[str] = None) -> Dict[str, Any]:
    """
    Retrieve user information via Okta Workflows.
    """
    if not access_token:
        return authorization_required_error("read_user", "User information lookup")

    scope_check = check_scope(
        access_token,
        TOOL_SCOPES.get("read_user", []),
        tool_key="read_user",
    )
    if scope_check.get("status") != "success":
        return scope_check

    logger.info("Reading user info: %s", user_login)
    return call_okta_workflow("read_user", user_login, reason)


@mcp.tool
def reset_password(user_login: str, reason: str, access_token: Optional[str] = None) -> Dict[str, Any]:
    """
    Trigger a password reset for a given user.
    """
    if not access_token:
        return authorization_required_error("reset_password", "Password reset")

    scope_check = check_scope(
        access_token,
        TOOL_SCOPES.get("reset_password", []),
        tool_key="reset_password",
    )
    if scope_check.get("status") != "success":
        return scope_check

    logger.info("Resetting password for: %s", user_login)
    return call_okta_workflow("reset_password", user_login, reason)


@mcp.tool
def suspend_user(user_login: str, reason: str, access_token: Optional[str] = None) -> Dict[str, Any]:
    """
    Suspend a user via Okta Workflows.
    """
    if not access_token:
        return authorization_required_error("suspend_user", "User suspension")

    scope_check = check_scope(
        access_token,
        TOOL_SCOPES.get("suspend_user", []),
        tool_key="suspend_user",
    )
    if scope_check.get("status") != "success":
        return scope_check

    logger.info("Suspending user: %s", user_login)
    return call_okta_workflow("suspend_user", user_login, reason)


@mcp.tool
def analyze_user_with_external_context(
    user_login: str,
    reason: str,
    access_token: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Run combined anomaly and impossible-travel analysis and enrich with user context.

    Returns a high-level risk level and contributing factors.
    """
    if not access_token:
        return authorization_required_error(
            "analyze_user_with_external_context",
            "Comprehensive analysis",
        )

    scope_check = check_scope(
        access_token,
        TOOL_SCOPES.get("analyze_user_with_external_context", []),
        tool_key="analyze_user_with_external_context",
    )
    if scope_check.get("status") != "success":
        return scope_check

    logger.info("Comprehensive analysis for: %s", user_login)

    try:
        logs_response = call_okta_workflow("search_logs", user_login, reason)
        if logs_response.get("status") != "success":
            logger.error("Failed to retrieve logs in comprehensive analysis")
            return {"status": "error", "error": "Failed to retrieve logs"}

        logs_data = logs_response.get("result", {})
        analysis_result = extract_and_analyze_logs(logs_data)

        user_info = call_okta_workflow("read_user", user_login, reason)

        user_context: Dict[str, Any] = {}
        if user_info.get("status") == "success":
            result = user_info.get("result", {})
            if isinstance(result, dict):
                user_context = {
                    "title": result.get("title", "Unknown"),
                    "division": result.get("division", "Unknown"),
                    "department": result.get("department", "Unknown"),
                }

        risk_level = "low"
        risk_factors: List[str] = []

        if analysis_result["anomaly_analysis"].get("is_anomalous"):
            risk_level = "medium"
            score = analysis_result["anomaly_analysis"].get("mean_anomaly_score")
            risk_factors.append(f"ML anomaly detected (score: {score})")

        if analysis_result["travel_analysis"].get("is_suspicious"):
            risk_level = "high"
            count = len(
                analysis_result["travel_analysis"].get("suspicious_travels", []),
            )
            risk_factors.append(f"Suspicious travel events ({count} instances)")

        return {
            "status": "success",
            "user": user_login,
            "risk_level": risk_level,
            "risk_factors": risk_factors,
            "user_context": user_context,
            "analysis": {
                "total_logs": analysis_result["total_logs"],
                "anomaly_analysis": analysis_result["anomaly_analysis"],
                "travel_analysis": analysis_result["travel_analysis"],
            },
        }

    except Exception as exc:
        logger.error("Error in comprehensive analysis: %s", str(exc))
        logger.exception(exc)
        return {"status": "error", "error": str(exc)}


@mcp.tool
def notify_user(
    from_email: str,
    to_email: str,
    subject: str,
    body: str,
) -> Dict[str, Any]:
    """
    Send a notification email based on the conversation context.

    Semantic expectations for the AI agent:
    - `from_email`: Sender identity (e.g., security-bot@example.com, admin@example.com).
    - `to_email`: Intended recipient (e.g., user's manager, security team).
    - `subject`: Short summary of the event or action which triggered the notification.
    - `body`: Detailed explanation covering:
        * what happened,
        * what actions were taken,
        * why this notification is needed,
        * relevant user/incident context.
    """
    payload = {
        "from": from_email,
        "to": to_email,
        "subject": subject,
        "body": body,
    }

    result = call_okta_workflow_generic("notify_user", payload)

    if result.get("status") != "success":
        return {
            "status": "error",
            "error": "Failed to send notification",
            "details": result,
        }

    return {
        "status": "success",
        "message": f"Notification sent to {to_email}",
    }
