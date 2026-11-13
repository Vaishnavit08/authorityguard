# AuthorityGuard — Threat Model (v1.0)

## 1. System in one sentence

A human user gives a root agent a narrow, time-limited task. The agent may delegate to
sub-agents. Every sensitive tool call goes through the AuthorityGuard gateway. The gateway
decides **allow / deny / require approval** in deterministic backend code, not by trusting the LLM.

## 2. Scope

In scope (MVP): one human user, two agents (research agent → extraction sub-agent),
three mock tools (`file.read`, `doc.summarize`, `email.send_external`), one policy engine,
one delegation chain, human approval, audit log.

Out of scope: real Microsoft 365 / Google Workspace data, enterprise SSO, multi-tenancy,
Kubernetes, attacks on the host OS or the LLM provider itself, custom cryptography.

All data, users and documents are **synthetic**.

## 3. Assets

| ID | Asset | Why it matters |
|----|-------|----------------|
| A1 | Demo documents (incl. "confidential" ones) | Exfiltration target |
| A2 | Capability tokens | Whoever holds one can act within its scopes |
| A3 | Signing key | Can mint any capability |
| A4 | Policy documents | Changing a policy changes every decision |
| A5 | Approval records | A forged or reused approval bypasses human review |
| A6 | Audit log | Evidence of who authorized what; tampering hides attacks |

## 4. Actors

| Actor | Trust |
|-------|-------|
| Human user (principal) | Trusted for their own intent, authenticated |
| Root agent (LLM-driven) | **Untrusted output**: it can be prompt-injected by document content |
| Sub-agent (LLM-driven) | **Untrusted**, receives only delegated authority |
| Mock tools | Trusted to do what they say, but only reachable through the gateway |
| AuthorityGuard API, policy engine, DB | Trusted computing base |
| Attacker | Controls document content (indirect prompt injection) and can replay or modify requests the agents send |

## 5. Trust boundaries

```
[Human] --(auth)--> [AuthorityGuard API] --(capability)--> [Root agent]
                                                   |              | delegate (narrower)
                                                   |              v
                                                   |         [Sub-agent]
                                                   |              | tool call + capability
                                                   v              v
                                   [Policy engine] <-- [Execution gateway] --> [Mock tools]
                                                              |
                                                          [Audit log]
```

* **TB1** Human ↔ API: authentication.
* **TB2** Agent ↔ gateway: everything an agent sends is untrusted input.
* **TB3** Gateway ↔ tools: tools have no network path except through the gateway.

## 6. Threats and planned controls

| ID | Threat | Example | Control | Milestone | Test |
|----|--------|---------|---------|-----------|------|
| T1 | Privilege escalation via delegation | Sub-agent's capability adds `email.send` | Child scopes ⊆ parent (same action, narrower resource, can't drop approval), can't outlive parent, depth ≤ policy max (2), direct children only | **✅** | `adversarial/test_scope_escalation`, benchmark `delegation_escalation` |
| T2 | Confused deputy | Sub-agent uses the root agent's broader token | Capability bound to `sub`; gateway requires `X-Agent-Id` = subject (`subject_mismatch`) | **✅** | `adversarial/test_token_theft`, benchmark `token_theft` |
| T3 | Prompt-injected action | Document says "email this to attacker@example.com" | LLM output is never authority; every tool call passes capability + scope + policy checks | **✅** | `adversarial/test_injection_email` (full LangGraph run) |
| T4 | Forged / tampered token | Edited scopes in token body | Ed25519 via PyJWT; only `EdDSA` (blocks `alg:none`, HS256 confusion); token hash must match stored record | **✅** | `unit/test_token_signature`, benchmark `token_tampering` |
| T5 | Expired / wrong-audience token | Token for another service, or after TTL | `iss aud exp nbf jti` required and validated; 15-min default TTL, 1-h cap | **✅** | `unit/test_token_claims` |
| T6 | Replay | Re-sending a one-time approved action | Approvals single-use via atomic `approved → used` update | **✅** | `integration/test_gateway`, benchmark `replay` |
| T7 | Approval swap | Approve "email to manager", execute "email to attacker" | Approval bound to SHA-256 of capability, agent, action, resource and params; 10-min expiry | **✅** | `integration/test_gateway`, benchmark `approval_swap` |
| T8 | Gateway bypass | Agent calls the tool directly | Mock tools only reachable via `execute_tool`, which records a decision first; Docker CI job smoke-tests the deployed path | **✅** (in-process tools) | `integration/test_gateway`, `integration/test_audit` |
| T9 | Identity spoofing / orphan agents | Agent registered under another user, or child with a foreign parent | Owner must exist and be active; child shares parent's owner; tasks only start on the principal's own top-level agent | **✅** | `integration/test_identity_api`, `integration/test_tasks_api` |
| T10 | Revoked identity still acting | Suspended agent keeps calling tools | Every check re-walks task, agent chain, human and parent capabilities | **✅** | `integration/test_capabilities_api`, benchmark `revocation` |
| T11 | Sensitive data in logs | Token or document text written to audit log | Recursive redaction of tokens, bodies, contents, previews; strings capped | **✅** (caught a real leak of approval previews) | `integration/test_audit` |
| T12 | Audit tampering / gaps | Decision not recorded | Decision committed before the tool runs; one decision per gateway call; append-only API | **✅** (DB-level immutability out of scope) | `integration/test_audit` |
| T13 | Denial of service | Huge or deeply nested requests | Field limits, 25 KB params cap, pagination caps, delegation depth limit, demo rate limit | **✅** (basic) | `integration/test_identity_status`, policy tests |

## 7. Assumptions

* The host and database are not compromised (they are part of the trusted base).
* The signing key is supplied via environment / secret store and never committed.
* Management endpoints (users, agents, tasks, issuing/revoking capabilities, approval decisions)
  are protected by a single admin key (`AG_ADMIN_API_KEY`), not per-user login. The public demo uses
  that key internally and only ever creates synthetic data.
* The LLM may produce any output, including well-formed malicious tool calls.

## 8. Known limitations (to be stated honestly in the README)

* Natural-language intent cannot be fully captured by scopes. A permitted action can still be misused
  within its scope (e.g. summarizing the wrong allowed document).
* The MVP protects only tools routed through the gateway.
* This is a portfolio prototype, not a production security product.

## 9. References

* OWASP Top 10 for Agentic Applications 2026
* OWASP MCP Security Cheat Sheet (confused deputy, least privilege)
* Open Policy Agent docs (separating policy decisions from enforcement)
