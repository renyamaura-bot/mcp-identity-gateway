"""
FastMCP server: suspend_user / unsuspend_user

This module exposes MCP tools for suspending and unsuspending users
through Okta Workflows, and records transaction-level audit logs in
JSON Lines format.

Intended usage:
- Called as an MCP server from an AI chat client (Claude, ChatGPT, etc.).
- All Okta Workflows access is performed via environment-configured URLs
  and tokens. No secrets are hard-coded in this file.
"""

import os
import json
import uuid
import logging
from typing import Dict, Any, Optional
from datetime import datetime

import requests
from fastmcp import FastMCP

# ==============================================================
# Logging configuration
# ==============================================================

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

# ==============================================================
# FastMCP server initialization
# ==============================================================

mcp = FastMCP("Okta Suspend/Unsuspend")

# ==============================================================
# Environment configuration
# ==============================================================

AUDIT_LOG_DIR = os.getenv("AUDIT_LOG_DIR", "/tmp/okta_audit")
os.makedirs(AUDIT_LOG_DIR, exist_ok=True)
AUDIT_LOG_FILE = os.path.join(AUDIT_LOG_DIR, "ai_actions.jsonl")

# Okta Workflows URLs and tokens (must be provided via environment variables)
SUSPEND_USER_URL = os.getenv("OKTA_WF_SUSPEND_USER_URL")
SUSPEND_USER_TOKEN = os.getenv("OKTA_WF_SUSPEND_USER_TOKEN")
UNSUSPEND_USER_URL = os.getenv("OKTA_WF_UNSUSPEND_USER_URL")
UNSUSPEND_USER_TOKEN = os.getenv("OKTA_WF_UNSUSPEND_USER_TOKEN")

logger.info("MCP Server initialized (Okta Suspend/Unsuspend)")

# ==============================================================
# Okta Workflows invocation helpers
# ==============================================================


def execute_workflow(
    url: Optional[str],
    token: Optional[str],
    user_login: str,
    reason: str,
    additional_data: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Invoke an Okta Workflows HTTP flow via POST.

    Parameters:
        url:
            HTTP endpoint URL of the Workflows flow.
        token:
            SSWS token used as an Authorization header.
        user_login:
            User login (e.g., email address) that identifies the target user.
        reason:
            Reason string describing why this action is executed.
        additional_data:
            Optional additional payload fields.

    Returns:
        A dictionary with:
            - status: "success" or "error"
            - result: Response JSON on success
            - error: Error message on failure
            - response: Raw response text on HTTP error
    """
    if not url or not token:
        logger.error("Workflow URL or token is not configured")
        return {
            "status": "error",
            "error": "Workflow URL or token not configured",
        }

    payload: Dict[str, Any] = {
        "user_login": user_login,
        "reason": reason,
    }
    if additional_data:
        payload.update(additional_data)

    headers = {
        "Authorization": f"SSWS {token}",
        "Content-Type": "application/json",
    }

    try:
        logger.info("Calling workflow for user: %s", user_login)

        response = requests.post(
            url,
            headers=headers,
            json=payload,
            timeout=30,
        )

        if response.status_code == 200:
            logger.info("Workflow executed successfully")
            return {
                "status": "success",
                "result": response.json(),
            }

        logger.error("Workflow failed: HTTP %s", response.status_code)
        return {
            "status": "error",
            "error": f"HTTP {response.status_code}",
            "response": response.text,
        }

    except Exception as exc:
        logger.error("Workflow execution error: %s", str(exc))
        return {
            "status": "error",
            "error": str(exc),
        }


# ==============================================================
# Audit logging
# ==============================================================


def save_audit_log(
    transaction_id: str,
    action: str,
    user: str,
    reasoning: str,
    status: str,
    rollback_of: Optional[str] = None,
) -> None:
    """
    Append a single audit log entry in JSON Lines format.

    Parameters:
        transaction_id:
            Unique identifier for this action (typically a UUID).
        action:
            Action name, e.g. "suspend_user" or "unsuspend_user".
        user:
            A user login identifier (e.g. email address).
        reasoning:
            Textual reasoning provided by the AI for this action.
        status:
            "success" or "error".
        rollback_of:
            Optional transaction_id of the original action being rolled back.
    """
    entry = {
        "transaction_id": transaction_id,
        "timestamp": datetime.utcnow().isoformat(),
        "action": action,
        "user": user,
        "reasoning": reasoning,
        "status": status,
        "rollback_of": rollback_of,
    }

    try:
        with open(AUDIT_LOG_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        logger.debug("Audit log saved: %s", transaction_id)
    except Exception as exc:
        logger.error("Failed to save audit log: %s", str(exc))


# ==============================================================
# MCP tool: suspend_user
# ==============================================================


@mcp.tool
def suspend_user(
    user_login: str,
    ai_reasoning: str,
) -> Dict[str, Any]:
    """
    Suspend a user account via Okta Workflows.

    Parameters:
        user_login:
            User login (e.g. email address).
        ai_reasoning:
            Reasoning string generated by the AI explaining why suspension
            is appropriate.

    Returns:
        {
            "status": "success" or "error",
            "transaction_id": "<uuid>",
            "user": "<user_login>",
            "error": "<error_message or None>",
        }
    """
    transaction_id = str(uuid.uuid4())

    logger.info("Suspending user: %s", user_login)
    logger.info("AI reasoning: %s", ai_reasoning)

    # Execute Okta Workflows flow
    result = execute_workflow(
        url=SUSPEND_USER_URL,
        token=SUSPEND_USER_TOKEN,
        user_login=user_login,
        reason=ai_reasoning,
    )

    # Write audit log
    save_audit_log(
        transaction_id=transaction_id,
        action="suspend_user",
        user=user_login,
        reasoning=ai_reasoning,
        status=result["status"],
    )

    return {
        "status": result["status"],
        "transaction_id": transaction_id,
        "user": user_login,
        "error": result.get("error"),
    }


# ==============================================================
# MCP tool: unsuspend_user
# ==============================================================


@mcp.tool
def unsuspend_user(
    user_login: str,
    transaction_id: str,
    reason: str = "Manual rollback",
) -> Dict[str, Any]:
    """
    Reactivate a previously suspended user (rollback operation).

    Parameters:
        user_login:
            User login (e.g. email address).
        transaction_id:
            Transaction ID of the original suspend_user operation.
        reason:
            Human-readable reason string for the rollback.

    Returns:
        {
            "status": "success" or "error",
            "transaction_id": "<new uuid>",
            "rollback_of": "<original transaction_id>",
            "user": "<user_login>",
            "error": "<error_message or None>",
        }
    """
    new_transaction_id = str(uuid.uuid4())

    logger.info("Unsuspending user: %s", user_login)
    logger.info("Rollback of transaction: %s", transaction_id)

    # Execute Okta Workflows flow
    result = execute_workflow(
        url=UNSUSPEND_USER_URL,
        token=UNSUSPEND_USER_TOKEN,
        user_login=user_login,
        reason=f"Rollback: {reason}",
        additional_data={"transaction_id": transaction_id},
    )

    # Write audit log
    save_audit_log(
        transaction_id=new_transaction_id,
        action="unsuspend_user",
        user=user_login,
        reasoning=f"Rollback of {transaction_id}",
        status=result["status"],
        rollback_of=transaction_id,
    )

    return {
        "status": result["status"],
        "transaction_id": new_transaction_id,
        "rollback_of": transaction_id,
        "user": user_login,
        "error": result.get("error"),
    }


# ==============================================================
# MCP tool: get_audit_log
# ==============================================================


@mcp.tool
def get_audit_log(
    user_login: Optional[str] = None,
    limit: int = 10,
) -> Dict[str, Any]:
    """
    Retrieve recent audit log entries.

    Parameters:
        user_login:
            Optional filter by user login. If provided, only entries whose
            'user' matches this value are returned.
        limit:
            Maximum number of entries to return (from the end of the file).

    Returns:
        {
            "status": "success" or "error",
            "entries": [ ... ],
            "count": <int>,
            "error": "<message>"  # only when status == "error"
        }
    """
    entries = []

    if not os.path.exists(AUDIT_LOG_FILE):
        return {
            "status": "success",
            "entries": [],
            "count": 0,
        }

    try:
        with open(AUDIT_LOG_FILE, "r", encoding="utf-8") as f:
            lines = f.readlines()

        # Get the latest 'limit' entries
        for line in lines[-limit:]:
            line = line.strip()
            if not line:
                continue

            data = json.loads(line)

            if user_login and data.get("user") != user_login:
                continue

            entries.append(data)

    except Exception as exc:
        logger.error("Failed to read audit log: %s", str(exc))
        return {
            "status": "error",
            "error": str(exc),
        }

    return {
        "status": "success",
        "entries": entries,
        "count": len(entries),
    }


# ==============================================================
# Main entrypoint (FastMCP server)
# ==============================================================

if __name__ == "__main__":
    logger.info("Starting MCP Server: Okta Suspend/Unsuspend")

    if not all(
        [SUSPEND_USER_URL, SUSPEND_USER_TOKEN, UNSUSPEND_USER_URL, UNSUSPEND_USER_TOKEN]
    ):
        logger.warning("Some environment variables are missing:")
        logger.warning("  SUSPEND_USER_URL set: %s", bool(SUSPEND_USER_URL))
        logger.warning("  SUSPEND_USER_TOKEN set: %s", bool(SUSPEND_USER_TOKEN))
        logger.warning("  UNSUSPEND_USER_URL set: %s", bool(UNSUSPEND_USER_URL))
        logger.warning("  UNSUSPEND_USER_TOKEN set: %s", bool(UNSUSPEND_USER_TOKEN))

    logger.info("Available tools:")
    logger.info("  - suspend_user(user_login, ai_reasoning)")
    logger.info("  - unsuspend_user(user_login, transaction_id, reason)")
    logger.info("  - get_audit_log(user_login, limit)")

    mcp.run()
