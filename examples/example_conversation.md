# Example: Incident Response Conversation with AI Agent and MCP Gateway

## Scenario

A security analyst is investigating potential suspicious activity for a user account. She starts a conversation with an AI agent that has access to the mcp-identity-gateway MCP tools. The workflow demonstrates how the AI can analyze, recommend, and execute identity operations while maintaining a full audit trail.

---

## Step 1: Analyst initiates authorization and requests analysis

**Analyst:** "I'm concerned about alice.johnson@example.com. Her account had some unusual login failures recently. Can you analyze her activity over the past 24 hours?"

**AI Agent:** I'll help you investigate. Let me first request authorization to access logs and perform analysis.

```
→ initiate_device_auth(tools=["search_logs", "read_user", "analyze_user_with_external_context"])

Response:
{
  "status": "success",
  "device_code": "XYZABC123",
  "user_code": "WXYZ-1234",
  "verification_uri_complete": "https://example.okta.com/device?user_code=WXYZ-1234",
  "expires_in": 600,
  "scopes": ["mcp:logs:read", "mcp:user:read:basic", "mcp:user:read:full", "mcp:analyze:ml"],
  "message": "Visit: https://example.okta.com/device?user_code=WXYZ-1234 to approve"
}
```

**AI Agent:** "I need you to visit the verification URL and approve access to logs and analysis tools. I'll wait."

**Analyst:** [Visits URL and clicks approve]

**AI Agent:** "Thank you. Now let me complete the authorization."

```
→ complete_device_auth(device_code="XYZABC123")

Response:
{
  "status": "success",
  "access_token": "eyJraWQiOiI...",
  "user_id": "security_analyst_01",
  "scopes": ["mcp:logs:read", "mcp:user:read:basic", "mcp:user:read:full", "mcp:analyze:ml"]
}
```

---

## Step 2: AI performs comprehensive analysis

**AI Agent:** "Now I'll analyze alice.johnson@example.com's activity."

```
→ analyze_identity_state(
    user="alice.johnson@example.com",
    time_range_hours=24,
    reason="Security investigation initiated by analyst",
    access_token="eyJraWQiOiI..."
  )

Response:
{
  "status": "success",
  "user": "alice.johnson@example.com",
  "time_range_hours": 24,
  "risk_level": "high",
  "behavior_summary": "Analyzed 42 events for alice.johnson@example.com in the last 24 hours: 8 auth failures, 3 MFA events, 1 password reset, 2 high-severity events.",
  "risk_reasons": [
    "Multiple failed authentication attempts (8) in a short period",
    "Password reset occurred along with multiple authentication failures"
  ],
  "recommended_actions": [
    {
      "action": "force_password_reset",
      "reason": "Signs of possible account compromise"
    },
    {
      "action": "terminate_active_sessions",
      "reason": "Terminate active sessions to contain potential access"
    }
  ],
  "notify": [
    {
      "role": "security_team",
      "reason": "High-risk activity detected for this user"
    }
  ],
  "vector_context": {
    "indexed": true,
    "index_id": "idx-550e8400",
    "similar_behaviors": [
      {
        "id": "idx-440f9511",
        "user": "bob.smith@example.com",
        "risk_level": "high",
        "similarity": 0.87,
        "behavior_summary": "Analyzed 38 events for bob.smith@example.com in the last 24 hours: 7 auth failures, 2 MFA events, 1 password reset, 3 high-severity events."
      }
    ]
  }
}
```

**AI Agent:** "The analysis shows a **high-risk** pattern. Here's what I found:

- **8 failed login attempts** in the past 24 hours
- **1 password reset** combined with failed logins (sign of account takeover)
- **Similar past incident**: bob.smith@example.com had a very similar pattern (87% match) which turned out to be a compromised account

The system recommends: force password reset, terminate sessions, and notify the security team.

**What would you like to do?**"

---

## Step 3: Analyst authorizes suspension and notification

**Analyst:** "This looks like a compromise. Let's suspend her account to prevent further damage, and notify the security team."

**AI Agent:** "I'll request authorization to perform these write operations."

```
→ initiate_device_auth(tools=["suspend_user", "notify_user"])

Response:
{
  "status": "success",
  "device_code": "YZAB456789",
  "user_code": "MNOP-5678",
  "verification_uri_complete": "https://example.okta.com/device?user_code=MNOP-5678",
  "expires_in": 600,
  "scopes": ["mcp:user:write"]
}
```

**Analyst:** [Visits URL and approves write operations]

**AI Agent:** [Completes device auth]

**AI Agent:** "Authorization granted. Suspending account and sending notification..."

```
→ suspend_user(
    user_login="alice.johnson@example.com",
    ai_reasoning="Account shows high-risk compromise signals: 8 failed logins, password reset, similar to confirmed incident. Analyst authorized suspension. Recommended action: isolate account pending investigation.",
    access_token="eyJraWQiOiI..."
  )

Response:
{
  "status": "success",
  "transaction_id": "txn-550e8400-e29b-41d4-a716-446655440000",
  "user": "alice.johnson@example.com",
  "error": null
}
```

**Audit log entry written to `ai_actions.jsonl`:**

```json
{
  "transaction_id": "txn-550e8400-e29b-41d4-a716-446655440000",
  "timestamp": "2025-01-15T14:32:45.123456Z",
  "action": "suspend_user",
  "user": "alice.johnson@example.com",
  "reasoning": "Account shows high-risk compromise signals: 8 failed logins, password reset, similar to confirmed incident. Analyst authorized suspension. Recommended action: isolate account pending investigation.",
  "status": "success",
  "rollback_of": null
}
```

**AI Agent:** Now notifying the security team:

```
→ notify_user(
    from_email="security-bot@example.com",
    to_email="security-team@example.com",
    subject="Account Suspension: alice.johnson@example.com",
    body="An account has been suspended due to compromise indicators:\n\n- User: alice.johnson@example.com\n- Risk Level: HIGH\n- Signals: 8 failed login attempts, password reset in suspicious pattern\n- Similar Past Incident: bob.smith@example.com (87% pattern match, confirmed compromise)\n- Action Taken: Account suspended to prevent unauthorized access\n- Transaction ID: txn-550e8400-e29b-41d4-a716-446655440000\n\nPlease investigate further and contact the user to verify if they initiated the password reset.",
    access_token="eyJraWQiOiI..."
  )

Response:
{
  "status": "success",
  "message": "Notification sent to security-team@example.com"
}
```

**AI Agent:** "✓ Account suspended (Transaction ID: txn-550e8400-e29b-41d4-a716-446655440000)\n✓ Security team notified\n\nAll actions have been recorded with reasoning in the audit log. If the investigation later determines this was a false positive, the account can be unsuspended with a rollback reference."

---

## Step 4: Later—Investigation reveals false positive

(Some time later)

**Security Analyst:** "We've confirmed with Alice that the password reset and login failures were due to her traveling and trying to access from a new IP. She approved the reset. Let's restore her account."

**AI Agent:** "I'll unsuspend her account and log the rollback."

```
→ unsuspend_user(
    user_login="alice.johnson@example.com",
    transaction_id="txn-550e8400-e29b-41d4-a716-446655440000",
    reason="Investigation confirmed travel and user-approved password reset. False positive."
  )

Response:
{
  "status": "success",
  "transaction_id": "txn-660f9511-f40c-52e5-b827-557766551111",
  "rollback_of": "txn-550e8400-e29b-41d4-a716-446655440000",
  "user": "alice.johnson@example.com",
  "error": null
}
```

**Audit log entry for rollback:**

```json
{
  "transaction_id": "txn-660f9511-f40c-52e5-b827-557766551111",
  "timestamp": "2025-01-15T16:00:00.000000Z",
  "action": "unsuspend_user",
  "user": "alice.johnson@example.com",
  "reasoning": "Rollback of txn-550e8400-e29b-41d4-a716-446655440000. Investigation confirmed travel and user-approved password reset. False positive.",
  "status": "success",
  "rollback_of": "txn-550e8400-e29b-41d4-a716-446655440000"
}
```

**AI Agent:** "✓ Account restored\n✓ Rollback logged with reference to the original suspension\n\nThe complete audit trail is now available showing:\n1. Why the account was suspended (high-risk signals + analyst authorization)\n2. Why the suspension was reversed (investigation outcome + user confirmation)\n\nThis record can be used for post-incident review and compliance reporting."

---

## Summary

This example demonstrates:

- **Explicit authorization**: The AI requests and obtains device authorization with specific scopes at each stage.
- **Comprehensive analysis**: The `analyze_identity_state` tool provides risk assessment, recommended actions, and contextual information from similar past incidents.
- **Explainable audit trail**: Every action (suspend, unsuspend, notify) is recorded with reasoning that humans can read and understand.
- **Reversibility**: The unsuspend action explicitly references the original transaction, creating a clear rollback chain for audit and forensics.
- **Collaboration**: The analyst makes the final decision; the AI provides analysis and executes authorized actions.
