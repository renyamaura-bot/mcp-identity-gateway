# Executive Summary for CISO and Audit

## Why this gateway exists

AI agents are rapidly becoming operational tools within security teams and identity operations. A CISO may delegate incident response tasks like user account suspension, password reset, and security notifications to an AI agent. However, exposing powerful identity APIs directly to AI introduces control and accountability gaps:

- **Loss of control**: The AI operates on implicit logic ("if the user appears risky, suspend them"). There is no explicit authorization boundary, and governance teams cannot easily see or audit why an action occurred.
- **Audit trail opacity**: Standard identity logs record *what* happened (account suspended at 14:32 UTC) but not *why* the decision was made. If an AI made an incorrect suspension, forensics become difficult.
- **Fragmented view**: Identity risk often requires correlating multiple data sources (authentication logs, impossible travel, anomalous behavior). These insights exist in separate systems with no unified narrative.

This gateway was designed to address these gaps by introducing explicit scopes, transaction-level audit trails, and semantic normalization.

## What this gateway does

**1. Access control via explicit scopes**

The AI must first obtain authorization via an OAuth Device Authorization Grant. Scopes are assigned based on which tools the AI intends to use (e.g., `mcp:user:write` for suspension, `mcp:logs:read` for log search). This ensures that even if the AI is compromised, it can only perform actions within the granted scope.

**2. Okta Workflows as the execution layer**

Rather than calling Okta APIs directly, all operations flow through Okta Workflows HTTP endpoints. Workflows can include policy checks, multi-step approvals, notifications, and audit hooks before the final action is executed. This provides a policy layer between the AI and the identity system.

**3. Explainable audit trails**

Every AI-driven action is recorded in JSONL format with:
- Transaction ID (unique identifier for the action)
- Timestamp
- Action name (e.g., `suspend_user`)
- Target user
- AI reasoning (text summary of why the action was recommended)
- Status (success or error)
- Rollback tracking (if this action reverses a prior action)

**4. Normalized identity events and risk signals**

Okta System Logs are normalized into a semantic schema, making it easier for AI agents to reason over identity events consistently. The gateway also applies heuristic risk analysis (failed login counts, MFA patterns, impossible travel) and can embed behavior summaries into a searchable vector database for pattern detection.

## What problems it addresses

**Problem: Loss of control over AI-driven operations**

*Solution*: Explicit scope-based authorization and Okta Workflows policies ensure the AI can only perform actions within defined boundaries, and those actions are subject to Workflows policy logic.

**Problem: Lack of explainability in audit trails**

*Solution*: The JSONL audit log includes the AI's reasoning, making it possible to trace every decision and understand why a user account was suspended or a password was reset.

**Problem: Fragmented view of identity risk**

*Solution*: The semantic event model normalizes Okta logs, and the vector database enables similarity search across past incidents, providing context for current decision-making.

## How to read this repository

**For a technical deep dive**, start with `docs/whitepaper.md`. It covers architecture, threat model, data flows, and design decisions.

**For governance and risk context**, review this summary and then examine:
- `src/okta_workflows.py` — How authorization and scope checking work.
- `src/okta_audit_and_rollback.py` — How audit logs are structured and rollback is tracked.
- `examples/audit-log-sample.jsonl` — Concrete examples of audit entries.

**For a realistic scenario**, read `examples/example_conversation.md` to see how an analyst and AI work together, step by step, during an incident response.

---

**Important caveat**: This is an experimental reference implementation. It is intended to support governance discussions and architectural planning. Before deploying in a production environment, conduct a thorough security and compliance review with your risk and legal teams.
