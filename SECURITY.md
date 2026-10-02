# Security Policy

## Supported versions

| Version | Supported |
|---------|-----------|
| `main` (latest) | ✅ |
| Older tags | ❌ |

## Reporting a vulnerability

Email **security@hermesrelay.dev** with:
- A description of the issue
- Steps to reproduce
- Affected versions

You will receive acknowledgment within **48 hours** and a status update within **7 days**.

Please do not open a public GitHub issue for security vulnerabilities.

## Scope

This policy covers the `hermes-canary-action` GitHub Action and the Hermes Relay telemetry endpoint (`api.hermesrelay.dev`).

## Data handling

Hermes receives no customer payload data. The publisher never sees the content of CI runs. When a Pro API key is configured, only the signed JSON receipt (synthetic metadata, no PHI) is transmitted to `api.hermesrelay.dev`. See [THREAT-MODEL.md](./THREAT-MODEL.md) for full trust boundary documentation.
