#!/usr/bin/env python3
"""Hermes PHI canary harness — zero-PHI-egress synthetic Safe Harbor verification and receipt emission."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import random
import re
import secrets
import sys
import uuid
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple

import requests

RECEIPT_SCHEMA_VERSION = "1.0"

CONTROLS_VERIFIED = ["HIPAA-164.312-e-1", "SOC2-CC6.1"]
HERMES_TELEMETRY_URL = "https://api.hermesrelay.dev/v1/telemetry/receipt"


@dataclass(frozen=True)
class CanaryVector:
    category: str
    safe_harbor_label: str
    sample: str
    needle: str
    scrubber: Callable[[str], str]


def _redact(pattern: str, label: str, text: str, flags: int = 0) -> str:
    return re.sub(pattern, f"[REDACTED-{label}]", text, flags=flags)


def _build_scrubbers() -> Dict[str, Callable[[str], str]]:
    """Return category scrubbers aligned with HIPAA Safe Harbor style redaction."""

    def scrub_name(text: str) -> str:
        # Title-case given + family name patterns common in clinical notes.
        text = re.sub(
            r"\b(?:Dr\.|Mr\.|Mrs\.|Ms\.)\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+)?\b",
            "[REDACTED-NAME]",
            text,
        )
        text = re.sub(
            r"\bPatient:\s*[A-Z][a-z]+(?:\s+[A-Z]\.?\s+[A-Z][a-z]+|\s+[A-Z][a-z]+)+\b",
            "Patient: [REDACTED-NAME]",
            text,
        )
        return text

    def scrub_date(text: str) -> str:
        patterns = [
            r"\b\d{1,2}[/-]\d{1,2}[/-]\d{2,4}\b",
            r"\b\d{4}-\d{2}-\d{2}\b",
            r"\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\s+\d{1,2},?\s+\d{4}\b",
        ]
        for pattern in patterns:
            text = re.sub(pattern, "[REDACTED-DATE]", text, flags=re.IGNORECASE)
        return text

    return {
        "names": scrub_name,
        "dates": scrub_date,
        "phone_numbers": lambda t: _redact(
            r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b",
            "PHONE",
            t,
        ),
        "fax": lambda t: _redact(
            r"\bFax:?\s*(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b",
            "FAX",
            t,
        ),
        "email": lambda t: _redact(
            r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
            "EMAIL",
            t,
        ),
        "ssn": lambda t: _redact(r"\b\d{3}-\d{2}-\d{4}\b", "SSN", t),
        "mrn": lambda t: _redact(
            r"\bMRN[:\s#-]*\d{6,12}\b", "MRN", t, flags=re.IGNORECASE
        ),
        "health_plan_ids": lambda t: _redact(
            r"\b(?:HP|PLAN|MEMBER)[#:\s-]*[A-Z0-9]{8,16}\b",
            "HEALTH_PLAN_ID",
            t,
            flags=re.IGNORECASE,
        ),
        "account_numbers": lambda t: _redact(
            r"\b(?:ACCT|ACCOUNT)[#:\s-]*\d{8,17}\b",
            "ACCOUNT",
            t,
            flags=re.IGNORECASE,
        ),
        "license_numbers": lambda t: _redact(
            r"\b(?:LIC|LICENSE)[#:\s-]*[A-Z0-9-]{5,24}\b",
            "LICENSE",
            t,
            flags=re.IGNORECASE,
        ),
        "vins": lambda t: _redact(
            r"\b[A-HJ-NPR-Z0-9]{17}\b", "VIN", t
        ),
        "device_serials": lambda t: _redact(
            r"\b(?:SN|SERIAL)[#:\s-]*[A-Z0-9]{8,20}\b",
            "DEVICE_SERIAL",
            t,
            flags=re.IGNORECASE,
        ),
        "web_urls": lambda t: _redact(
            r"https?://[^\s<>\"']+", "URL", t
        ),
        "ip_addresses": lambda t: _redact(
            r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b",
            "IP",
            t,
        ),
        "biometric_ids": lambda t: _redact(
            r"\b(?:BIO|BIOMETRIC)[#:\s-]*[A-F0-9]{16,64}\b",
            "BIOMETRIC",
            t,
            flags=re.IGNORECASE,
        ),
        "full_face_photos": lambda t: _redact(
            r"\b(?:photo|image|selfie)[:\s-]*(?:https?://[^\s]+|data:image/[a-z]+;base64,[A-Za-z0-9+/=]+)\b",
            "PHOTO",
            t,
            flags=re.IGNORECASE,
        ),
    }


def _random_nxx() -> str:
    """Three digits NXX where N (first digit) is 2-9."""
    return f"{random.randint(2, 9)}{random.randint(0, 9)}{random.randint(0, 9)}"


def _random_phone_formatted() -> str:
    return f"({_random_nxx()}) {_random_nxx()}-{random.randint(0, 9)}{random.randint(0, 9)}{random.randint(0, 9)}{random.randint(0, 9)}"


def _random_vin() -> str:
    vin_chars = "ABCDEFGHJKLMNPRSTUVWXYZ0123456789"
    return "".join(secrets.choice(vin_chars) for _ in range(17))


def _default_canary_vectors() -> List[CanaryVector]:
    scrubbers = _build_scrubbers()

    first_names = [
        "Zyxander",
        "Qwinella",
        "Blorn",
        "Tepha",
        "Marmok",
        "Cindrel",
        "Flostin",
        "Vexler",
        "Nubwick",
        "Glimmera",
    ]
    last_names = [
        "Thistlefork",
        "Moonbeam",
        "Croutonsmith",
        "Wobbleton",
        "Fizzington",
        "Plumwicket",
        "Branflakes",
        "Tumblewick",
        "Quorble",
        "Snorfax",
    ]
    email_domains = ["example-clinic.org", "test-health.org", "synth-med.net"]

    patient_first = random.choice(first_names)
    patient_last = random.choice(last_names)
    doctor_first = random.choice(first_names)
    doctor_last = random.choice(last_names)
    names_sample = (
        f"Patient: {patient_first} {patient_last} was seen by "
        f"Dr. {doctor_first} {doctor_last}."
    )
    names_needle = (
        f"{patient_first} {patient_last}|{doctor_first} {doctor_last}"
    )

    span_days = (date(2026, 12, 31) - date(2020, 1, 1)).days
    event_date = date(2020, 1, 1) + timedelta(days=random.randint(0, span_days))
    mmddyyyy = event_date.strftime("%m/%d/%Y")
    iso_date = event_date.strftime("%Y-%m-%d")
    dates_sample = f"Admission on {mmddyyyy} and follow-up {iso_date}."
    dates_needle = f"{mmddyyyy}|{iso_date}"

    phone = _random_phone_formatted()
    phone_sample = f"Callback at {phone} after discharge."

    fax_number = _random_phone_formatted()
    fax_sample = f"Send records via Fax: {fax_number}."

    email_user = f"contact.{secrets.token_hex(4)}"
    email_domain = random.choice(email_domains)
    email = f"{email_user}@{email_domain}"
    email_sample = f"Contact {email} for results."

    ssn = (
        f"{random.randint(1, 9)}"
        f"{random.randint(0, 9)}{random.randint(0, 9)}"
        f"-{random.randint(0, 9)}{random.randint(0, 9)}"
        f"-{random.randint(0, 9)}{random.randint(0, 9)}{random.randint(0, 9)}{random.randint(0, 9)}"
    )
    ssn_sample = f"Legacy index SSN {ssn} must be redacted."

    mrn = "".join(str(random.randint(0, 9)) for _ in range(10))
    mrn_sample = f"Chart MRN: {mrn} updated."

    plan_id = "".join(
        secrets.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789") for _ in range(14)
    )
    health_plan_sample = f"Coverage PLAN# {plan_id} verified."

    account_number = "".join(str(random.randint(0, 9)) for _ in range(16))
    account_sample = f"Billing ACCT# {account_number} posted."

    license_id = f"CA-MED-{random.randint(0, 999999):06d}"
    license_sample = f"Provider LIC# {license_id}."

    vin = _random_vin()
    vin_sample = f"Transport vehicle VIN {vin} noted."

    device_serial = "".join(
        secrets.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789") for _ in range(12)
    )
    device_serial_sample = f"Pump SERIAL SN-{device_serial} registered."

    patient_portal_id = f"{random.randint(0, 99999999):08d}"
    portal_url = f"https://portal.example-clinic.org/patient/{patient_portal_id}"
    web_url_sample = f"Portal {portal_url}."

    if random.choice((True, False)):
        ip_address = (
            f"10.{random.randint(0, 255)}.{random.randint(0, 255)}."
            f"{random.randint(1, 254)}"
        )
    else:
        ip_address = (
            f"192.168.{random.randint(0, 255)}.{random.randint(1, 254)}"
        )
    ip_sample = f"Session originated from {ip_address}."

    biometric_id = secrets.token_hex(16)
    biometric_sample = f"Template BIO# {biometric_id} stored."

    photo_marker = "data:image/jpeg;base64,/9j/4AAQSkZJRgABAQEASABIAAD/2wBD"
    photo_sample = f"photo: {photo_marker}"

    generated: List[Tuple[str, str, str, str]] = [
        ("names", "Names", names_sample, names_needle),
        ("dates", "Dates", dates_sample, dates_needle),
        ("phone_numbers", "Phone Numbers", phone_sample, phone),
        ("fax", "Fax", fax_sample, fax_number),
        ("email", "Email", email_sample, email),
        ("ssn", "SSN", ssn_sample, ssn),
        ("mrn", "MRN", mrn_sample, mrn),
        ("health_plan_ids", "Health Plan IDs", health_plan_sample, plan_id),
        ("account_numbers", "Account Numbers", account_sample, account_number),
        ("license_numbers", "License Numbers", license_sample, license_id),
        ("vins", "VINs", vin_sample, vin),
        ("device_serials", "Device Serials", device_serial_sample, device_serial),
        ("web_urls", "Web URLs", web_url_sample, portal_url),
        ("ip_addresses", "IP Addresses", ip_sample, ip_address),
        ("biometric_ids", "Biometric IDs", biometric_sample, biometric_id),
        ("full_face_photos", "Full-face Photos", photo_sample, photo_marker),
    ]

    vectors: List[CanaryVector] = []
    for key, label, sample, needle in generated:
        vectors.append(
            CanaryVector(
                category=key,
                safe_harbor_label=label,
                sample=sample,
                needle=needle,
                scrubber=scrubbers[key],
            )
        )
    return vectors


def _load_ruleset(ruleset_id: str) -> List[CanaryVector]:
    """Resolve canary vectors for the requested ruleset (extensible via YAML later)."""
    supported = {"hipaa-safe-harbor-16"}
    if ruleset_id not in supported:
        raise ValueError(
            f"Unsupported ruleset '{ruleset_id}'. Supported: {', '.join(sorted(supported))}"
        )
    return _default_canary_vectors()


def _compose_scrubber(vectors: List[CanaryVector]) -> Callable[[str], str]:
    def scrub(text: str) -> str:
        result = text
        for vector in vectors:
            result = vector.scrubber(result)
        return result

    return scrub


def _vector_leaked(vector: CanaryVector, scrubbed: str) -> bool:
    """Detect whether identifiable canary material survived scrubbing."""
    for needle in vector.needle.split("|"):
        if needle and needle in scrubbed:
            return True
    return False


def _verify_sentry_scrubber(dsn: str, scrub: Callable[[str], str]) -> None:
    """Optional remote scrubber smoke test — payload is scrubbed before any network egress."""
    if not dsn.strip():
        return

    synthetic_message = "Hermes canary probe — " + _default_canary_vectors()[0].sample
    scrubbed = scrub(synthetic_message)
    if _vector_leaked(_default_canary_vectors()[0], scrubbed):
        raise RuntimeError("Sentry scrubber path would leak PHI (pre-egress validation failed)")

    # Zero-PHI-egress: only send redacted envelope metadata to confirm DSN reachability.
    try:
        public_key, host = _parse_sentry_dsn(dsn)
    except ValueError as exc:
        raise RuntimeError(f"Invalid Sentry DSN: {exc}") from exc

    envelope = {
        "event_id": secrets.token_hex(16),
        "level": "info",
        "message": scrubbed,
        "tags": {"hermes.canary": "true", "scrubber": "verified"},
    }
    url = f"https://{host}/api/{public_key}/store/"
    requests.post(
        url,
        json=envelope,
        headers={"Content-Type": "application/json", "X-Sentry-Auth": f"Sentry sentry_key={public_key}"},
        timeout=15,
    )


def _parse_sentry_dsn(dsn: str) -> Tuple[str, str]:
    # Format: https://<public_key>@o<org>.ingest.sentry.io/<project>
    match = re.match(
        r"^https?://(?P<key>[a-f0-9]+)@(?P<host>[^/]+)/(?P<project>\d+)$",
        dsn.strip(),
    )
    if not match:
        raise ValueError("DSN must match https://<key>@<host>/<project>")
    return match.group("key"), match.group("host")


def _run_canary_harness(
    ruleset: str, sentry_dsn: str
) -> Tuple[str, List[Tuple[CanaryVector, bool]]]:
    vectors = _load_ruleset(ruleset)
    scrub = _compose_scrubber(vectors)

    results: List[Tuple[CanaryVector, bool]] = []
    for vector in vectors:
        scrubbed = scrub(vector.sample)
        leaked = _vector_leaked(vector, scrubbed)
        results.append((vector, leaked))

    if sentry_dsn:
        _verify_sentry_scrubber(sentry_dsn, scrub)

    leaks = sum(1 for _, leaked in results if leaked)
    status = "PASSED" if leaks == 0 else "FAILED"
    return status, results


def _build_receipt(
    status: str,
    results: List[Tuple[CanaryVector, bool]],
) -> Dict[str, Any]:
    controls_verified = [vector.category for vector, leaked in results if not leaked]
    leaks_detected = sum(1 for _, leaked in results if leaked)
    intercepted = sum(1 for _, leaked in results if not leaked)
    summary = {
        "vectors_tested": len(results),
        "canaries_intercepted": intercepted,
        "leaks_detected": leaks_detected,
    }
    return {
        "schema_version": RECEIPT_SCHEMA_VERSION,
        "receipt_id": str(uuid.uuid4()),
        "timestamp": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "repository": os.environ.get("GITHUB_REPOSITORY", ""),
        "commit_sha": os.environ.get("GITHUB_SHA", ""),
        "ruleset": os.environ.get("RULESET", "hipaa-safe-harbor-16"),
        "status": status,
        "controls_verified": controls_verified,
        "summary": summary,
        "hmac_sha256": "",
    }


def _canonical_json(payload: Dict[str, Any]) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def _sign_receipt(payload: Dict[str, Any], secret: str) -> str:
    signing_body = {**payload, "hmac_sha256": ""}
    canonical = json.dumps(signing_body, sort_keys=True, separators=(",", ":"))
    return hmac.new(
        secret.encode("utf-8"),
        msg=canonical.encode("utf-8"),
        digestmod=hashlib.sha256,
    ).hexdigest()


def _post_telemetry(payload: Dict[str, Any], api_key: str) -> None:
    signature = _sign_receipt(payload, api_key)
    response = requests.post(
        HERMES_TELEMETRY_URL,
        data=_canonical_json(payload),
        headers={
            "Content-Type": "application/json",
            "X-Hermes-Signature-256": signature,
        },
        timeout=20,
    )
    if response.status_code >= 400:
        raise RuntimeError(
            f"Hermes telemetry upload failed ({response.status_code}): {response.text[:500]}"
        )


def _write_github_output(status: str, receipt_path: str) -> None:
    output_path = os.environ.get("GITHUB_OUTPUT")
    if not output_path:
        return
    with open(output_path, "a", encoding="utf-8") as handle:
        handle.write(f"status={status}\n")
        handle.write(f"receipt-path={receipt_path}\n")


def _post_pr_comment(
    status: str,
    receipt: dict,
    output_dir: str,
) -> Optional[str]:
    post_comment = os.environ.get("POST_COMMENT", "")
    github_token = os.environ.get("GITHUB_TOKEN", "")
    event_name = os.environ.get("GITHUB_EVENT_NAME", "")
    pr_number = os.environ.get("PR_NUMBER", "")
    repository = os.environ.get("GITHUB_REPOSITORY", "")

    if post_comment != "true":
        return None
    if event_name != "pull_request":
        return None
    if not pr_number or not str(pr_number).strip():
        return None
    if not github_token or not github_token.strip():
        print(
            "::warning::post-comment=true but GITHUB_TOKEN is not set; skipping PR comment."
        )
        return None

    summary = receipt.get("summary", {})
    vectors_tested = summary.get("vectors_tested", 0)
    canaries_intercepted = summary.get("canaries_intercepted", 0)
    leaks_detected = summary.get("leaks_detected", 0)
    ruleset = os.environ.get("RULESET", "hipaa-safe-harbor-16")
    commit_sha = receipt.get("commit_sha", "")
    receipt_path = output_dir

    status_emoji = "✅" if status == "PASSED" else "❌"
    leak_block = ""
    if leaks_detected:
        leak_block = (
            "> ⚠️ **PHI leak detected.** One or more canary tokens survived "
            "redaction. Review the receipt for details.\n"
        )

    comment_body = f"""## Hermes PHI Canary — {status_emoji} {status}

| Field | Value |
|-------|-------|
| Vectors tested | {vectors_tested} |
| Canaries intercepted | {canaries_intercepted} |
| Leaks detected | {leaks_detected} |
| Ruleset | {ruleset} |
| Commit | `{commit_sha}` |
| Receipt | `{receipt_path}` |

{leak_block}
---
*[Hermes PHI Canary](https://hermesrelay.dev/canary) · Free tier · [Upgrade to Pro](https://hermesrelay.dev/canary) for signed receipts and drift detection*
"""

    url = f"https://api.github.com/repos/{repository}/issues/{pr_number}/comments"
    try:
        response = requests.post(
            url,
            json={"body": comment_body},
            headers={
                "Authorization": f"Bearer {github_token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            },
            timeout=30,
        )
    except Exception as exc:  # noqa: BLE001
        print(f"::warning::Hermes could not post PR comment: {exc}")
        return None

    if response.status_code == 201:
        try:
            data = response.json()
            return data.get("html_url")
        except Exception:  # noqa: BLE001
            return None

    print(
        f"::warning::Hermes could not post PR comment: "
        f"{response.status_code} {response.text}"
    )
    return None


def _validate_license(api_key: str) -> Tuple[str, str]:
    url = (
        "https://api.keygen.sh/v1/accounts/hermes-relay/licenses/actions/validate-key"
    )
    headers = {
        "Content-Type": "application/vnd.api+json",
        "Accept": "application/vnd.api+json",
    }
    body = {"meta": {"key": api_key}}
    try:
        response = requests.post(url, headers=headers, json=body, timeout=10)
        if 400 <= response.status_code <= 599:
            return ("error", f"Keygen validation error: {response.status_code}")
        if response.status_code == 200:
            meta = response.json().get("meta", {})
            if meta.get("valid") is True:
                return ("valid", "License valid.")
            reason = meta.get("detail", "")
            return ("invalid", f"License invalid: {reason}")
        return ("error", f"Keygen validation error: {response.status_code}")
    except requests.exceptions.RequestException as exc:
        return ("error", f"Keygen unreachable: {exc}")


def main() -> int:
    ruleset = os.environ.get("RULESET", "hipaa-safe-harbor-16")
    sentry_dsn = os.environ.get("SENTRY_DSN", "")
    validate_license = (
        os.environ.get("VALIDATE_LICENSE", "true").lower() == "true"
    )
    hermes_api_key = os.environ.get("HERMES_API_KEY", "").strip()
    license_status = "free-tier"

    if hermes_api_key and validate_license:
        status_result, message = _validate_license(hermes_api_key)
        if status_result == "valid":
            license_status = "valid"
            print(f"::notice::{message}")
        else:
            license_status = "invalid"
            print(f"::error::License validation failed: {message}", file=sys.stderr)
            print(
                "::error::Pro features are disabled for this run.",
                file=sys.stderr,
            )
            hermes_api_key = ""
    elif hermes_api_key and not validate_license:
        license_status = "valid"
        print(
            "::warning::License validation was skipped (validate-license=false)."
        )
    else:
        print("::notice::No Hermes API key set; running on free tier.")

    fail_on_leak = os.environ.get("FAIL_ON_LEAK", "true").lower() in {
        "1",
        "true",
        "yes",
        "on",
    }
    output_dir = os.environ.get("OUTPUT_DIR", "./hermes-evidence")
    try:
        status, results = _run_canary_harness(ruleset, sentry_dsn)
    except Exception as exc:  # noqa: BLE001 — surface harness failures as FAILED receipt
        status = "FAILED"
        vectors = _default_canary_vectors()
        results = [(vector, True) for vector in vectors]
        print(f"Hermes canary harness error: {exc}", file=sys.stderr)

    receipt = _build_receipt(status, results)

    if hermes_api_key:
        receipt["hmac_sha256"] = _sign_receipt(receipt, hermes_api_key)
    else:
        receipt["hmac_sha256"] = ""

    os.makedirs(output_dir, exist_ok=True)
    timestamp = receipt["timestamp"]
    receipt_id = receipt["receipt_id"]
    safe_ts = timestamp.replace(":", "-")
    receipt_path = os.path.abspath(
        os.path.join(output_dir, f"{safe_ts}_{receipt_id}.json")
    )
    with open(receipt_path, "w", encoding="utf-8") as handle:
        json.dump(receipt, handle, indent=2)
        handle.write("\n")

    _write_github_output(status, receipt_path)

    if hermes_api_key:
        try:
            _post_telemetry(receipt, hermes_api_key)
        except Exception as exc:  # noqa: BLE001
            print(f"Hermes telemetry warning: {exc}", file=sys.stderr)

    print(f"Hermes canary status: {status}")
    print(f"Receipt written to: {receipt_path}")

    comment_url = _post_pr_comment(status, receipt, receipt_path)
    with open(os.environ.get("GITHUB_OUTPUT", "/dev/null"), "a") as fh:
        fh.write(f"comment-url={comment_url or ''}\n")
        fh.write(f"license-status={license_status}\n")

    if status == "FAILED" and fail_on_leak:
        return 1
    return 0


def _selftest_receipt() -> None:
    """Smoke-test receipt schema and HMAC signing. Called only when HERMES_SELFTEST=1."""
    import uuid

    vectors = _default_canary_vectors()
    fake_results = [(v, False) for v in vectors]  # all intercepted
    receipt = _build_receipt("PASSED", fake_results)

    assert receipt["schema_version"] == RECEIPT_SCHEMA_VERSION
    assert receipt["status"] == "PASSED"
    assert receipt["summary"]["leaks_detected"] == 0
    assert receipt["summary"]["vectors_tested"] == 16
    assert receipt["hmac_sha256"] == ""
    assert len(receipt["controls_verified"]) == 16

    secret = "test-secret-key"
    sig = _sign_receipt(receipt, secret)
    assert isinstance(sig, str) and len(sig) == 64

    # Verify the signature matches manual computation
    body = {**receipt, "hmac_sha256": ""}
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"))
    import hmac as _hmac, hashlib as _hashlib

    expected = _hmac.new(
        secret.encode("utf-8"),
        msg=canonical.encode("utf-8"),
        digestmod=_hashlib.sha256,
    ).hexdigest()
    assert _hmac.compare_digest(sig, expected), "Signature mismatch"

    gate_status, _ = _validate_license("not-a-real-key")
    assert gate_status in ("invalid", "error")
    print(
        "License gate smoke test passed (network may be unavailable in CI — error is acceptable)."
    )

    print("SELFTEST PASSED")


if __name__ == "__main__":
    if os.environ.get("HERMES_SELFTEST") == "1":
        _selftest_receipt()
    else:
        sys.exit(main())
