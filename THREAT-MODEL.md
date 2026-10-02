# Threat Model — Hermes PHI Canary

## What this action does

1. Materializes 16 synthetic HIPAA Safe Harbor canary vectors (no real patient data).
2. Applies the configured scrubber ruleset locally on the GitHub Actions runner.
3. Detects whether any raw canary token survives redaction.
4. Writes a JSON receipt to the runner workspace.
5. Optionally validates a Sentry DSN (scrubs before any network call).
6. Optionally POSTs a signed receipt to `api.hermesrelay.dev` when `hermes-api-key` is set.

## Trust boundaries

| Boundary | What crosses it | What does not cross it |
|----------|----------------|------------------------|
| Runner → Sentry (optional) | Scrubbed probe metadata only | Raw canary tokens, PHI |
| Runner → Hermes Relay (Pro, optional) | Signed JSON receipt (synthetic metadata) | Canary samples, customer pipeline data |
| Runner → GitHub | Workflow status, uploaded artifacts | Receipt contents (unless you upload them) |

## What the publisher receives

When `hermes-api-key` is configured, Hermes Relay receives:
- `receipt_id`, `timestamp`, `repository`, `commit_sha`
- `status` (PASSED / FAILED)
- `controls_verified` list
- `summary` counts (vectors tested, intercepted, leaked)

The publisher receives **no customer payload data, no PHI, no secrets, and no pipeline content**.

## Zero-PHI-egress guarantee

Canary strings are synthetic and do not meet the HIPAA definition of PHI under **45 CFR 160.103**. When scrubbing succeeds, no canary token leaves the runner in cleartext. Customers are responsible for ensuring their workflow does not route production ePHI through the canary harness.

## Secret handling

- `hermes-api-key` and `sentry-dsn` are passed as environment variables to the Python process. They are not logged, not written to the receipt, and not transmitted except to their respective endpoints.
- GitHub Actions masks secrets in runner logs automatically when declared under `secrets`.

## Signing

Pro receipts are signed with HMAC-SHA256 using `hermes-api-key` as the secret over the canonical JSON body. The signature is transmitted in the `X-Hermes-Signature-256` header. Verifiers can re-derive the signature from the receipt body and their key to confirm the receipt was not altered after the run.

## Out of scope

- Control design, BAA scope, and compliance program decisions remain the customer's responsibility.
- Hermes does not certify HIPAA compliance or SOC 2 conformance.
