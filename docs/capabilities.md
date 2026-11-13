# Capability tokens

A **capability** is a signed, short-lived permission slip that says exactly what one agent may do
for one task. Agents present it with every protected action; AuthorityGuard checks it every time.

## What a token contains

A JWT signed with **Ed25519** (`alg: EdDSA`). Decoded, the payload looks like:

```json
{
  "iss": "authorityguard",            // who issued it
  "aud": "authorityguard-gateway",    // who must accept it
  "sub": "<research-agent id>",       // the ONLY agent allowed to use it
  "jti": "<capability id>",           // unique id, used for revocation and lookup
  "iat": 1794571173, "nbf": 1794571173,
  "exp": 1794572073,                  // 15 minutes by default, 1 hour maximum
  "task_id": "<task id>",
  "principal_id": "<alice-demo id>",  // the human whose authority this is
  "scopes": [
    {"action": "file.read", "resource": "/demo/projects/*", "requires_approval": false},
    {"action": "doc.summarize", "resource": "*", "requires_approval": false}
  ],
  "depth": 0, "parent_jti": null      // used by delegation in Week 3
}
```

Anyone can *read* a JWT. The signature makes it impossible to *change* one without detection.

## How a token is checked

`POST /v1/capabilities/verify` runs every check, in order, and stops at the first failure:

| # | Check | Reason code on failure | Threat |
|---|-------|------------------------|--------|
| 1 | Well-formed JWT | `malformed` | T4 |
| 2 | Algorithm is exactly `EdDSA` | `invalid_algorithm` | T4 |
| 3 | Signature matches our public key | `invalid_signature` | T4 |
| 4 | Has `iss aud sub jti iat nbf exp` | `missing_claim` | T5 |
| 5 | Issuer / audience are ours | `wrong_issuer` / `wrong_audience` | T5 |
| 6 | Not expired, not before `nbf` | `expired` / `not_yet_valid` | T5 |
| 7 | We have a record of issuing this `jti` | `unknown_capability` | T4 |
| 8 | SHA-256 of the token matches that record | `token_mismatch` | T4 |
| 9 | Not revoked | `capability_revoked` | T10 |
| 10 | Task still active | `task_inactive` | T10 |
| 11 | Agent, every ancestor and the human are active | `agent_inactive` / `principal_inactive` | T10 |
| 12 | Presenting agent is the token's `sub` | `subject_mismatch` | T2 |

Steps 1–6 are cryptography (PyJWT). Steps 7–12 are **live state**: a perfectly signed token still stops
working the moment the task closes, the agent is suspended, or the capability is revoked.

## Keys

* The private key lives at `AG_SIGNING_KEY_PATH` (default `.keys/signing-ed25519.pem`, git-ignored).
* In `AG_ENV=dev` or `demo` it is generated automatically on first use. In any other environment it must exist.
* Each token header carries `kid` (a fingerprint of the public key) so keys can be rotated later.
* Tests use a fresh in-memory key and never touch the file.

## Delegation (Week 3)

`POST /v1/capabilities/delegate` takes the parent token, the delegator's agent id and the desired
scopes. The child capability is issued only if:

* the delegator is the parent token's subject, and the parent token passes every check above
* the target is a **direct child** of the delegator in the registered agent tree
* every requested scope is **within** a parent scope: same action, narrower or equal resource, and it
  keeps any `requires_approval` flag
* it does not outlive the parent (`ttl_exceeds_parent`), and depth stays ≤ the policy's
  `max_delegation_depth` (2)

At use time, revoking any ancestor capability disables all of its descendants
(`parent_capability_revoked`).
