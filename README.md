# mcp-identity-gateway

AI Agents and Identity Platforms: Auditability over Powerful APIs  
An MCP-based gateway design and reference implementation for Okta

This repository contains:

- A reference whitepaper describing an MCP-based gateway pattern between AI agents and identity platforms, with a focus on auditability and CISO-level concerns.
- Sample FastMCP-based integration modules for Okta and Okta Workflows, implementing:
  - User suspension and rollback
  - System log search and risk analysis
  - Password reset, user lookup, and notification flows
- Example audit and semantic event artifacts.

The implementation is designed to be vendor-neutral at the architectural level while using Okta and Okta Workflows as concrete examples.

---

## Repository layout

```text
mcp-identity-gateway/
  README.md              # This file
  docs/
    whitepaper.md        # Full design and evaluation paper
    architecture-overview.png   # Optional architecture diagram
    audit-log-sample.json       # Example AI action audit record
    semantic-event-sample.json  # Example normalized System Log event
  src/
    okta_audit_and_rollback.py  # FastMCP tools for suspend / unsuspend + audit logging
    okta_systemlog.py           # FastMCP tools for System Log search and vector store
    okta_workflows.py           # Consolidated FastMCP server integrating Okta Workflows
    __init__.py
```

You are expected to bring your own Okta tenant and Okta Workflows HTTP flows. The Python modules call those flows via environment-configured URLs and tokens.

---

## Components

- `docs/whitepaper.md`  
  Full write-up of the architecture, security model, and lessons learned. This is the primary document to share with CISOs, security architects, and auditors.

- `src/okta_workflows.py`  
  Main FastMCP server file that exposes tools such as:
  - `suspend_user`
  - `reactivate_user`
  - `reset_password`
  - `read_user`
  - `search_logs`
  - `analyze_identity_state`
  - `detect_anomalies_ml`
  - `detect_impossible_travel`
  - `notify_user`  
  It includes device authorization, scope checking, JWT validation, and risk / anomaly analysis logic.

- `src/okta_audit_and_rollback.py`  
  Focused module for:
  - Calling Okta Workflows HTTP flows for `suspend_user` and `unsuspend_user`
  - Writing transaction-level JSONL audit logs for AI-driven actions

- `src/okta_systemlog.py`  
  Focused module for:
  - Calling Okta Workflows to search System Logs
  - Storing and retrieving behavioral summaries in a local vector store (JSONL)

---

## Prerequisites

- Python 3.10+ (3.11 recommended)
- A working FastMCP environment and client (e.g., Claude Desktop, ChatGPT MCP, or another MCP-capable chat client)
- An Okta tenant with:
  - An authorization server for OAuth 2.0 / OIDC
  - An OIDC client (for device authorization)
  - Okta Workflows with HTTP flows for:
    - Suspend user
    - Unsuspend / reactivate user
    - Reset password
    - Search System Logs
    - Read user attributes
    - Send notification emails
- Python dependencies (install via `pip` or your preferred tool):
  - `fastmcp`
  - `requests`
  - `PyJWT`
  - `scikit-learn`

---

## Environment configuration

The modules read configuration from environment variables. Typical variables include:

### Identity platform and OAuth

- `OKTA_ISSUER`  
  Example: `https://your-domain.okta.com/oauth2/default`

- `OKTA_CLIENT_ID`  
  Client ID of the OIDC app used for device authorization.

- `OKTA_CLIENT_SECRET`  
  Client secret for the same app.

- `OKTA_AUTH_SERVER_ID`  
  Authorization server ID (e.g., `default` or a custom ID).

### Okta Workflows HTTP flows

- `OKTA_WF_RESET_PASSWORD_URL`  
- `OKTA_WF_RESET_PASSWORD_TOKEN`

- `OKTA_WF_SUSPEND_USER_URL`  
- `OKTA_WF_SUSPEND_USER_TOKEN`

- `OKTA_WF_UNSUSPEND_USER_URL`  
- `OKTA_WF_UNSUSPEND_USER_TOKEN`

- `OKTA_WF_SEARCH_LOGS_URL`  
- `OKTA_WF_SEARCH_LOGS_TOKEN`

- `OKTA_WF_READ_USER_URL`  
- `OKTA_WF_READ_USER_TOKEN`

- `OKTA_WF_NOTIFY_USER_URL`  
- `OKTA_WF_NOTIFY_USER_TOKEN`

### Audit and vector store

- `AUDIT_LOG_DIR`  
  Directory for JSONL audit logs of AI-driven actions.  
  Default: `/tmp/okta_audit`

- `VECTOR_DB_PATH`  
  Path to the JSONL file used as a simple vector store for behavioral summaries.  
  Default: `./vector_db.jsonl`

These flows are expected to be implemented on the Okta Workflows side and to accept/return JSON payloads consistent with the Python code.

---

## How to use (high-level)

1. **Prepare Okta Workflows**  
   - Create HTTP-triggered flows for:
     - Suspend / unsuspend user
     - Reset password
     - Search System Logs
     - Read user attributes
     - Send notification emails  
   - Configure authentication (e.g., API token in a header) and copy the URLs and tokens into environment variables.

2. **Configure OAuth and device authorization**  
   - Create an OAuth / OIDC client for the MCP gateway.  
   - Enable device authorization grant on the authorization server.  
   - Set `OKTA_ISSUER`, `OKTA_CLIENT_ID`, `OKTA_CLIENT_SECRET`, and `OKTA_AUTH_SERVER_ID`.

3. **Set environment variables**  
   - Export all required `OKTA_WF_*`, `AUDIT_LOG_DIR`, and `VECTOR_DB_PATH` values in your runtime environment.

4. **Run the FastMCP server**  
   - Use your FastMCP runtime to expose `src/okta_workflows.py` (and optionally the other modules) as an MCP server.  
   - Configure your MCP client to call this server (for example, via a command like `python src/okta_workflows.py` or an equivalent entrypoint, depending on your FastMCP setup).

5. **Connect from an AI client**  
   - Configure your AI chat client (Claude, ChatGPT, etc.) to use the MCP server.  
   - The AI client will:
     - Run a device authorization flow via the gateway  
     - Obtain a token with approved scopes  
     - Call tools like `analyze_identity_state`, `suspend_user`, or `notify_user` as part of conversations

6. **Review audit artifacts**  
   - Inspect `AUDIT_LOG_DIR` for JSONL audit records of AI-driven actions.  
   - Inspect `VECTOR_DB_PATH` for behavioral summary vectors and metadata.  
   - Refer to `docs/audit-log-sample.json` and `docs/semantic-event-sample.json` for format references.

---

## Whitepaper

The design, threat model, and recommendations for CISOs are documented in:

- `docs/whitepaper.md`

Suggested PDF title when exporting:

- `AI-Agents-and-Identity-Platforms-Auditability-over-Powerful-APIs.pdf`

You can render the Markdown to PDF using your preferred tool (for example, VS Code extensions, Pandoc, or a documentation pipeline) when sharing externally.

---

## Intended use

This repository is intended as:

- A reference architecture for connecting AI agents to identity platforms through an MCP gateway.
- A concrete example of how to:
  - Enforce scopes and device authorization for AI clients
  - Derive risk and anomaly signals from System Logs
  - Record AI-driven actions with transaction-level audit logs and reasoning
- A starting point for organizations that want to evaluate AI-assisted identity operations under strong auditability and governance constraints.

It is not a turnkey product. You are expected to:

- Adapt the Okta Workflows flows to your own tenant and policies.
- Adjust scopes, tools, and governance rules to match your risk appetite.
- Review and extend the code before using it in any production context.
