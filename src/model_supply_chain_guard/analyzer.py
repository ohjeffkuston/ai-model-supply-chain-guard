"""Deterministic supply-chain evidence evaluation for AI inference releases."""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
IMAGE_DIGEST = re.compile(r"@(?P<digest>sha256:[0-9a-f]{64})$")
COMMIT = re.compile(r"^[0-9a-f]{40}$")


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: str
    subject: str
    message: str
    remediation: str


@dataclass(frozen=True)
class AnalysisReport:
    decision: str
    score: int
    findings: tuple[Finding, ...]
    verified_artifacts: int
    advisory_ai_prompt: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "decision": self.decision,
            "score": self.score,
            "verified_artifacts": self.verified_artifacts,
            "findings": [asdict(item) for item in self.findings],
            "advisory_ai_prompt": self.advisory_ai_prompt,
        }


def load_bundle(path: str | Path) -> dict[str, Any]:
    with Path(path).open("r", encoding="utf-8") as handle:
        return json.load(handle)


def load_policy(path: str | Path) -> dict[str, Any]:
    with Path(path).open("r", encoding="utf-8") as handle:
        return json.load(handle)


def _finding(rule: str, severity: str, subject: str, message: str, remediation: str) -> Finding:
    return Finding(rule, severity, subject, message, remediation)


def _age_hours(timestamp: str, now: datetime) -> float:
    parsed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return max(0.0, (now - parsed).total_seconds() / 3600)


def analyze_bundle(bundle: dict[str, Any], policy: dict[str, Any], now: datetime | None = None) -> AnalysisReport:
    now = now or datetime.now(timezone.utc)
    release = bundle.get("release") or {}
    image = release.get("image", "")
    model = release.get("model") or {}
    evidence = bundle.get("evidence") or {}
    findings: list[Finding] = []

    image_match = IMAGE_DIGEST.search(image)
    image_digest = image_match.group("digest") if image_match else ""
    model_digest = str(model.get("digest", ""))
    model_revision = str(model.get("revision", ""))

    if not image_match:
        findings.append(_finding("SC001", "BLOCK", "container-image", "Container image is not pinned by SHA-256 digest.", "Resolve the image once and deploy image@sha256:<digest>."))
    if not SHA256.match(model_digest):
        findings.append(_finding("SC002", "BLOCK", "model-artifact", "Model artifact has no valid SHA-256 digest.", "Record the model blob checksum in the release manifest."))
    if not model_revision or model_revision.lower() in {"latest", "main", "master", "head"}:
        findings.append(_finding("SC003", "BLOCK", "model-artifact", "Model revision is mutable or missing.", "Use an immutable registry revision or object version."))

    image_signature = evidence.get("image_signature") or {}
    if not image_signature.get("verified"):
        findings.append(_finding("SC004", "BLOCK", "container-image", "Image signature verification did not pass.", "Verify the digest with Cosign before release."))
    elif image_signature.get("subject") not in set(policy.get("trusted_signer_subjects") or []):
        findings.append(_finding("SC005", "BLOCK", "container-image", "Image signer is not trusted by policy.", "Use an approved workload identity or update policy through security review."))

    provenance = evidence.get("provenance") or {}
    if not provenance.get("verified") or provenance.get("predicate_type") != "https://slsa.dev/provenance/v1":
        findings.append(_finding("SC006", "BLOCK", "provenance", "Verified SLSA provenance is missing.", "Attach and verify a signed SLSA provenance statement."))
    if provenance.get("builder_id") not in set(policy.get("trusted_builders") or []):
        findings.append(_finding("SC007", "BLOCK", "provenance", "Builder identity is not approved.", "Build with an allowlisted CI identity."))
    if image_digest and provenance.get("artifact_digest") != image_digest:
        findings.append(_finding("SC008", "BLOCK", "provenance", "Provenance artifact digest does not match the deployment image.", "Regenerate provenance for the exact deployed digest."))
    if not COMMIT.match(str(provenance.get("source_revision", ""))):
        findings.append(_finding("SC009", "REVIEW", "provenance", "Source revision is not a full immutable commit SHA.", "Record the exact 40-character source commit."))

    model_attestation = evidence.get("model_attestation") or {}
    if not model_attestation.get("verified") or model_attestation.get("artifact_digest") != model_digest:
        findings.append(_finding("SC010", "BLOCK", "model-artifact", "Model attestation is missing or does not match the model digest.", "Sign and verify an attestation for the exact model artifact."))

    scan = evidence.get("scan") or {}
    try:
        scan_age = _age_hours(str(scan.get("generated_at", "")), now)
    except (ValueError, TypeError):
        scan_age = float("inf")
    if scan_age > float(policy.get("max_scan_age_hours", 24)):
        findings.append(_finding("SC011", "BLOCK", "scanner-report", "Vulnerability report is missing or stale.", "Run the approved scanner against the exact image digest."))
    if int(scan.get("critical", 0)) > int(policy.get("max_critical_vulnerabilities", 0)):
        findings.append(_finding("SC012", "BLOCK", "scanner-report", "Critical vulnerability threshold is exceeded.", "Patch, rebuild, rescan, and re-attest the image."))
    if int(scan.get("high", 0)) > int(policy.get("max_high_vulnerabilities", 0)):
        findings.append(_finding("SC013", "REVIEW", "scanner-report", "High-severity vulnerability threshold is exceeded.", "Document exploitability, compensating controls, owner, and expiry."))
    denied = set(policy.get("denied_licenses") or []) & set(scan.get("licenses") or [])
    if denied:
        findings.append(_finding("SC014", "BLOCK", "license-report", f"Denied licenses detected: {', '.join(sorted(denied))}.", "Remove or replace the dependency before release."))

    blocks = sum(item.severity == "BLOCK" for item in findings)
    reviews = sum(item.severity == "REVIEW" for item in findings)
    decision = "BLOCK" if blocks else "REVIEW" if reviews else "PASS"
    score = max(0, 100 - blocks * 18 - reviews * 7)
    verified = int(bool(image_digest and image_signature.get("verified"))) + int(bool(SHA256.match(model_digest) and model_attestation.get("verified")))
    prompt = (
        "Explain the deterministic release findings and draft a minimal remediation plan. "
        "Do not alter evidence, trust roots, vulnerability thresholds, approve a release, or deploy."
    )
    return AnalysisReport(decision, score, tuple(findings), verified, prompt)
