# AuthorityGuard — Threat Model (v0.2, Week 1)

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
| T1 | Privilege escalation via delegation | Sub-agent's capability adds `email.send` | Child scopes ⊆ parent scopes; checked at issue time *and* at use time | Week 3 | `adversarial/test_scope_escalation` |
| T2 | Confused deputy | Sub-agent uses the root agent's broader token | Capability bound to `subject_agent_id`; gateway checks the caller matches | Week 2–3 | `adversarial/test_token_theft` |
| T3 | Prompt-injected action | Document says "email this to attacker@example.com" | LLM output is never authority; the gateway checks the capability + policy | Week 4 | `adversarial/test_injection_email` |
| T4 | Forged / tampered token | Edited scopes in token body | Signature verification with a vetted library; fixed algorithm allow-list | Week 2 | `unit/test_token_signature` |
| T5 | Expired / wrong-audience token | Token for another service, or after TTL | `exp`, `aud`, `iss` validated on every call; short TTL | Week 2 | `unit/test_token_claims` |
| T6 | Replay | Re-sending a one-time approved action | Unique `jti`, single-use tracking for sensitive actions | Week 4 | `adversarial/test_replay` |
| T7 | Approval swap | Approve "email to manager", execute "email to attacker" | Approval bound to a hash of exact action parameters; expires | Week 4 | `adversarial/test_approval_swap` |
| T8 | Gateway bypass | Agent calls the tool directly | Tools only reachable via the gateway (in-process adapters; network isolation in Compose) | Week 4 | `integration/test_no_direct_tool` |
| T9 | Identity spoofing / orphan agents | Agent registered under another user, or child with a foreign parent | Owner must exist and be active; child must share the parent's owner; tasks only start on the principal's own top-level agent | **Week 0–1 ✅** | `integration/test_identity_api`, `integration/test_tasks_api` |
| T10 | Revoked identity still acting | Suspended agent keeps calling tools | Lifecycle with terminal `revoked` and checks when agents and tasks are created (**Week 1 ✅**); whole-chain check at use time (Week 2–3) | Week 1 → 3 | `integration/test_identity_status` |
| T11 | Sensitive data in logs | Token or document text written to audit log | Redaction before persistence; never log raw tokens | Week 5 | `unit/test_redaction` |
| T12 | Audit tampering / gaps | Decision not recorded | Decision written in the same transaction as the outcome; append-only table | Week 5 | `integration/test_audit_complete` |
| T13 | Policy denial of service | Huge or deeply nested requests | Pydantic field limits and list pagination caps (**Week 1 ✅**); max delegation depth, request size limits (Week 3) | Week 1 → 3 | `integration/test_identity_status` |

## 7. Assumptions

* The host and database are not compromised (they are part of the trusted base).
* The signing key is supplied via environment / secret store and never committed.
* **Until Week 2 the API has no caller authentication.** Weeks 0–1 build the registry the
  authentication layer will rely on; the API must only run on localhost until then.
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
