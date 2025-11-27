# mcp-identity-gateway

**AI Agents and Identity Platforms: Auditability over Powerful APIs**

An MCP-based gateway design and reference implementation for Okta.

## Overview

AI agents are becoming powerful tools for security operations and identity administration. However, directly exposing identity platform APIs (create user, reset password, suspend account) to AI agents introduces significant governance and audit risks. This repository demonstrates a gateway pattern where AI agents communicate through Model Context Protocol (MCP) tools, all backed by explicit audit trails that capture not just *what* happened, but *why* the AI made that decision.

The design emphasizes **explainability over raw API power**. Rather than giving AI agents unrestricted access to identity APIs, we introduce an MCP gateway that sits between the AI and Okta. All AI-driven operations pass through this gateway, are authorized via explicit scopes, and are recorded in transaction-level audit logs that include the AI's reasoning.

This repository is a **reference implementation**. It is intended to support governance discussions, proof-of-concept work, and architectural planning for organizations evaluating how to safely delegate identity operations to AI agents.

## Repository layout

```text
mcp-identity-gateway/
  README.md
  LICENSE
  docs/
    whitepaper.md
    Executive-Summary-for-CISO.md
    audit-log-sample.json
    semantic-event-sample.json
  examples/
    example_conversation.md
    audit-log-sample.jsonl
  src/
    __init__.py
    okta_audit_and_rollback.py
    okta_systemlog.py
    okta_workflows.py
```

## What this repository demonstrates

This repository contains three FastMCP server implementations that together form an AI-safe gateway to Okta:

- **MCP gateway between AI agents and Okta**: A clean abstraction where the AI agent calls MCP tools rather than Okta REST APIs directly.
- **Okta Workflows as the execution layer**: Operations like suspend user, reset password, and notify are executed via Okta Workflows HTTP flows, which themselves can include policy checks and approval steps.
- **Transaction-level AI audit logs**: Every action initiated by the AI is recorded in JSONL format, including the user, action, AI reasoning, timestamp, and outcome. Rollbacks are tracked via transaction IDs.
- **Semantic event normalization**: Okta System Logs are normalized into a consistent schema, allowing the AI to reason over identity events in a structured way.
- **Local vector store for behavioral analysis**: Event summaries are embedded and stored in a searchable JSONL vector database, enabling pattern detection and anomaly context.

## Components

**Documentation:**

- `docs/whitepaper.md` — Technical architecture and design rationale for security architects and IAM engineers.
- `docs/Executive-Summary-for-CISO.md` — High-level overview for CISOs and audit stakeholders covering governance, control, and risk mitigation.
- `docs/audit-log-sample.json` — Example of a single AI-driven action audit log entry showing transaction ID, action, reasoning, status, and timestamp.
- `docs/semantic-event-sample.json` — Example of a normalized semantic event derived from an Okta System Log, including actor, target, risk signals, and client context.

**Examples:**

- `examples/example_conversation.md` — Narrative walkthrough of a realistic incident response scenario: analyst queries user activity, AI analyzes logs, AI suspends account, and audit is recorded.
- `examples/audit-log-sample.jsonl` — Two sample JSONL lines showing a suspend action followed by a rollback (unsuspend) that references the original transaction.

**Source code:**

- `src/okta_workflows.py` — FastMCP server providing Device Authorization Grant, scope-based access control, log analysis, anomaly detection, and user operations (suspend, reset password, read user, notify).
- `src/okta_audit_and_rollback.py` — FastMCP server for suspend / unsuspend operations with explicit transaction-level audit logging in JSONL format.
- `src/okta_systemlog.py` — FastMCP server for semantic normalization of Okta System Logs, heuristic risk analysis, and OpenAI-powered behavior vectorization and similarity search.

## Prerequisites

**Python:** 3.9 or later.

**MCP client:** An MCP-capable AI client such as Claude Desktop, ChatGPT with MCP support, or a custom agent framework.

**Okta tenant:** You must have:

- An Okta organization with API access.
- An OAuth 2.0 authorization server.
- An OIDC client configured for Device Authorization Grant flow.
- Okta Workflows HTTP flows for: suspend user, unsuspend user, reset password, search system logs, read user, and notify user.

**Python dependencies:**

- fastmcp
- requests
- PyJWT
- scikit-learn
- openai
- numpy

## Environment configuration

All credentials and URLs are supplied via environment variables. No secrets are stored in this repository.

**OAuth / Device Authorization:**

- `OKTA_ISSUER` — Okta organization base URL (e.g., `https://myorg.okta.com`).
- `OKTA_CLIENT_ID` — OAuth client ID.
- `OKTA_CLIENT_SECRET` — OAuth client secret.
- `OKTA_AUTH_SERVER_ID` — Authorization server ID.

**Okta Workflows HTTP flows (URL + token for each):**

- `OKTA_WF_SUSPEND_USER_URL` / `OKTA_WF_SUSPEND_USER_TOKEN`
- `OKTA_WF_UNSUSPEND_USER_URL` / `OKTA_WF_UNSUSPEND_USER_TOKEN`
- `OKTA_WF_RESET_PASSWORD_URL` / `OKTA_WF_RESET_PASSWORD_TOKEN`
- `OKTA_WF_SEARCH_LOGS_URL` / `OKTA_WF_SEARCH_LOGS_TOKEN`
- `OKTA_WF_READ_USER_URL` / `OKTA_WF_READ_USER_TOKEN`
- `OKTA_WF_NOTIFY_USER_URL` / `OKTA_WF_NOTIFY_USER_TOKEN`

**Audit and vector storage:**

- `AUDIT_LOG_DIR` — Directory for storing JSONL audit logs (default: `/tmp/okta_audit`).
- `VECTOR_DB_PATH` — Path to the JSONL vector database (default: `./vector_db.jsonl`).

## Quick start

1. **Implement Okta Workflows HTTP flows.** In Okta Workflows, create HTTP-triggered flows for suspend_user, unsuspend_user, reset_password, search_logs (System Log API), read_user, and notify_user. Each flow should accept `user_login` and `reason` parameters. Document the HTTP endpoint URL and generate an API token for each flow.

2. **Set environment variables.** Create a `.env` file or export the variables listed in the Environment configuration section above. Ensure all OAuth and Workflows URLs and tokens are present.

3. **Install Python dependencies.** Run:

   ```bash
   pip install fastmcp requests PyJWT scikit-learn openai numpy
   ```

4. **Run the three MCP servers.** In separate terminals (or using a process manager), start each server:

   ```bash
   python src/okta_workflows.py
   python src/okta_systemlog.py
   python src/okta_audit_and_rollback.py
   ```

5. **Configure MCP client.** In your MCP-capable client (e.g., Claude Desktop, custom agent), add server configurations pointing to each of the three servers. Refer to your client's MCP documentation for details.

6. **Inspect audit logs and examples.** Review `examples/audit-log-sample.jsonl` and `examples/example_conversation.md` to understand the expected audit trail format and a realistic usage scenario.

7. **Test with analyze_identity_state.** Start with the `analyze_identity_state()` tool to verify log retrieval and semantic normalization. Then proceed to actions like `suspend_user()` once you confirm the audit trail is working.

---

**License:** MIT (see LICENSE file).

**Disclaimer:** This is a reference implementation for evaluation and architectural planning purposes. It is not production-hardened. Before using in a production environment, conduct a thorough security review, implement additional error handling, and ensure compliance with your organization's governance and audit policies.
