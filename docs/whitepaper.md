# AI Agents and Identity Platforms: Auditability over Powerful APIs

## 1. Introduction

Organizations increasingly leverage AI agents for operational tasks, including security incident response and identity governance. A natural use case is delegating identity actions—such as suspending a user account, resetting a password, or searching security logs—to an AI agent that can operate 24/7 and respond to threats faster than manual processes.

However, directly granting AI agents access to identity management APIs introduces significant risks:

- **Lack of explicit authorization**: If an AI makes a mistake, it is unclear what authorization gates should have prevented it.
- **Opaque decision-making**: Identity audit logs record actions but rarely explain the AI's reasoning.
- **Fragmented data**: The AI must correlate information across multiple systems to make sound decisions, but integration is ad-hoc.
- **Insufficient rollback capability**: If an AI-driven action is incorrect, reversing it requires manual intervention with poor audit tracking.

This whitepaper describes a reference architecture using Model Context Protocol (MCP) gateways, Okta Workflows, and semantic normalization to make AI-driven identity operations **auditable, explainable, and reversible**.

## 2. Design goals

1. **Auditability over raw power**: The gateway prioritizes comprehensive audit trails over unrestricted API access. Every action includes reasoning and can be linked to subsequent actions or rollbacks.

2. **Explicit authorization**: AI agents obtain tokens via Device Authorization Grant, with scopes that limit which tools (and therefore which actions) are available. Authorization is not implicit; it is explicit and revocable.

3. **Operational transparency**: Humans should be able to understand why an AI made a decision. Audit logs capture the AI's reasoning, the data it analyzed, and the action it took.

4. **Reversibility and rollback**: Actions can be undone with full audit tracking. A rollback action explicitly references the original transaction ID.

5. **Semantic normalization**: Identity events from Okta System Logs are normalized into a consistent schema, reducing the cognitive load on the AI and improving decision consistency.

6. **Stateless and cloud-friendly**: The design avoids server-side device session storage, allowing deployment in stateless environments like FastMCP Cloud.

## 3. Architecture overview

The system comprises three FastMCP servers and a network of Okta Workflows HTTP flows:

### 3.1 MCP Servers

**okta_workflows.py (MCP Server 1: Authorization and Operations)**

This server handles OAuth Device Authorization Grant, scope validation, and the core identity operations. It exposes tools for:

- Device authorization (initiate / complete device auth)
- Log analysis (search logs, detect anomalies via ML, detect impossible travel)
- User operations (read user, suspend user, reset password)
- Comprehensive analysis (combine anomaly detection with risk analysis)
- Notifications (send emails or Slack messages)

All tools check the AI's access token against required scopes before executing. Actual operations are delegated to Okta Workflows HTTP flows.

**okta_systemlog.py (MCP Server 2: Semantic Analysis and Vectorization)**

This server normalizes Okta System Logs into a semantic event schema and performs heuristic risk analysis. It exposes one main tool:

- `analyze_identity_state(user, time_range_hours)` — Fetches System Logs, normalizes them, applies risk analysis, and indexes the behavior summary as an embedding in a local JSONL vector database. It also searches for similar past behaviors to provide context.

**okta_audit_and_rollback.py (MCP Server 3: Action Logging and Reversibility)**

This server records all AI-driven actions in a transaction-level JSONL audit log and handles rollbacks. It exposes tools for:

- `suspend_user(user_login, ai_reasoning)` — Suspend a user and log the action with transaction ID and AI reasoning.
- `unsuspend_user(user_login, transaction_id)` — Reactivate a user, explicitly referencing the original transaction ID.
- `get_audit_log(user_login, limit)` — Retrieve recent audit entries (optionally filtered by user).

### 3.2 Okta Workflows HTTP Flows

Each MCP server calls Okta Workflows HTTP flows to perform the actual identity operations. These flows are the policy and execution layer:

- **suspend_user** — Receives user_login and reason; suspends the account; optionally notifies managers or security team.
- **unsuspend_user** — Reactivates a suspended user; includes transaction ID for audit trail linking.
- **reset_password** — Initiates a password reset for a user; may trigger email and MFA challenge.
- **search_logs** — Queries Okta System Logs API and returns events for the specified user and time range.
- **read_user** — Retrieves user profile information (name, department, current status).
- **notify_user** — Sends an email or notification to a user, manager, or security team.

## 4. Threat model

This design addresses the following threat scenarios:

**Scenario 1: Overly powerful AI agent (Unintentional harm)**

An AI agent with unrestricted API access might make mistakes (suspend the wrong user, reset the wrong password). The gateway mitigates this by:
- Limiting scope to specific operations (via OAuth scopes).
- Requiring explicit reasoning in the audit log (helps identify mistakes).
- Enabling easy rollback (unsuspend_user, etc.).
- Recording all actions for post-incident analysis.

**Scenario 2: Compromised AI model (Malicious or adversarial input)**

If an attacker injects malicious instructions into the AI's context, the scope-based authorization ensures the AI cannot exceed its granted permissions. Additionally:
- Okta Workflows can include policy checks (e.g., do not suspend executives without approval).
- Audit logs create a forensic trail.
- Human operators can quickly revoke device authorization tokens.

**Scenario 3: Auditor needs to trace a decision**

An auditor asks: "Why was user@example.com suspended?" The JSONL audit log directly answers this question by including the AI's reasoning, the analysis that led to the decision, and the timestamp. If the decision was incorrect, the unsuspend action is linked back to the original suspend via transaction ID.

**Out of scope (not addressed by this design):**

- Okta tenant compromise (if an attacker has administrative access to Okta itself, this design does not protect).
- Supply-chain attacks on dependencies (fastmcp, openai, sklearn, etc.).
- Physical security of infrastructure hosting the MCP servers.

## 5. Data flows

### 5.1 Device Authorization Flow

The AI client initiates device authorization:

```
AI Client
  → initiate_device_auth(tools=["suspend_user", "read_user"])
  → MCP Server (okta_workflows.py)
    → Compute scope union: mcp:user:write, mcp:user:read:basic
    → Call Okta Device Auth Endpoint
    ← Return: device_code, user_code, verification_uri_complete, expires_in
  ← Display verification URL to user
    
User visits URL, approves access scope.

AI Client
  → complete_device_auth(device_code=...)
  → MCP Server (okta_workflows.py)
    → Exchange device_code for access_token (at /v1/token)
    → Verify token signature using Okta JWKS
    → Extract scopes from token
    ← Return: access_token, user_id, scopes
```

From this point forward, the AI client includes `access_token` in all tool calls.

### 5.2 Log Analysis and Risk Assessment Data Flow

```
AI Client
  → analyze_identity_state(user="user@example.com", time_range_hours=24, access_token=...)
  → MCP Server (okta_systemlog.py)
    → Verify token has scope mcp:logs:read
    → Call Okta Workflows search_logs flow
      ← Fetch System Logs (raw Okta events)
    → Normalize each event to semantic schema
      - Extract: actor, target, category, action, severity, client IP, geo, outcome
    → Heuristic risk analysis
      - Count failed authentications, MFA events, password resets
      - Assign risk_level: low, medium, high, critical
      - List recommended actions
    → Embed behavior summary using OpenAI API
    → Store in local JSONL vector database
    → Search for similar past behaviors (cosine similarity)
    ← Return: risk_level, behavior_summary, recommended_actions, similar_past_behaviors
```

### 5.3 User Suspension with Audit Trail

```
AI Client (after analyzing risk)
  → suspend_user(user_login="user@example.com", ai_reasoning="...", access_token=...)
  → MCP Server (okta_workflows.py)
    → Verify token has scope mcp:user:write
    → Call Okta Workflows suspend_user flow
      → Workflow includes policy check, notification, etc.
      ← Confirm suspension
    ← Return: status=success, transaction_id=UUID
  
Simultaneously, MCP Server (okta_audit_and_rollback.py) writes:
  {
    "transaction_id": "550e8400-e29b-41d4-a716-446655440000",
    "timestamp": "2025-01-15T14:32:00Z",
    "action": "suspend_user",
    "user": "user@example.com",
    "reasoning": "ML anomaly score -0.45, impossible travel detected",
    "status": "success",
    "rollback_of": null
  }

Later, if the decision is reversed:

AI Client
  → unsuspend_user(
      user_login="user@example.com",
      transaction_id="550e8400-e29b-41d4-a716-446655440000",
      reason="False positive; travel was legitimate"
    )
  → MCP Server (okta_audit_and_rollback.py)
    → Call Okta Workflows unsuspend_user flow
    → Write new audit entry:
      {
        "transaction_id": "660f9511-f40c-52e5-b827-557766551111",
        "timestamp": "2025-01-15T15:00:00Z",
        "action": "unsuspend_user",
        "user": "user@example.com",
        "reasoning": "Rollback of 550e8400-e29b-41d4-a716-446655440000",
        "status": "success",
        "rollback_of": "550e8400-e29b-41d4-a716-446655440000"
      }
```

## 6. Lessons learned

- **Device Authorization Grant is essential**: Client credentials grant would require storing secrets in the AI agent. Device Authorization Grant allows the agent to authenticate without storing secrets, and the authorization can be easily revoked.

- **Scope validation at tool call time**: Rather than checking scopes once, each tool validates scopes on every call. This ensures that if the token is refreshed or revoked, the MCP server immediately denies access.

- **Workflows as a policy layer**: Delegating actual operations to Okta Workflows allows policies to be updated without code changes. A Workflow can include approval steps, policy checks, and audit hooks.

- **JSONL for audit logs**: JSONL (JSON Lines) is ideal for audit logs because each line is a complete, parseable record. It is easy to stream, query, and integrate with log aggregation tools (ELK, Splunk, etc.).

- **Semantic normalization is critical**: Without normalization, the AI must understand multiple event schemas (Okta System Log format, AD event format, etc.). Normalizing events into a common schema reduces complexity and improves decision quality.

- **Embedding and similarity search provide context**: When the AI is about to make a high-risk decision, querying similar past behaviors provides valuable context and can help identify patterns.

- **Stateless design**: Avoiding server-side state (like device session storage) makes the system suitable for serverless or cloud-native environments.

## 7. Intended use

This reference implementation is intended for:

- **Proof-of-concept projects**: Organizations evaluating how to safely delegate identity tasks to AI agents.
- **Governance and audit discussions**: Helping non-technical stakeholders understand how AI-driven identity operations can be auditable and reversible.
- **Architectural planning**: Providing a baseline that security and IAM teams can adapt to their own policies and compliance requirements.

It is **not** intended as a production-ready system without additional hardening, testing, and compliance review.

Recommended next steps for production deployment:

1. Conduct a security review with your cloud security and compliance teams.
2. Extend error handling and add circuit breakers for Okta API calls.
3. Implement centralized audit log forwarding to a SIEM or log aggregation system.
4. Add approval workflows for high-risk actions (e.g., require human sign-off before suspending an executive).
5. Implement rate limiting and DDoS protection for the MCP servers.
6. Test rollback procedures and ensure audit trail integrity.
