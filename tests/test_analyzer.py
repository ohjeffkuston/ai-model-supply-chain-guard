from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path

from model_supply_chain_guard.analyzer import analyze_bundle, load_bundle, load_policy

ROOT = Path(__file__).parents[1]
NOW = datetime(2026, 11, 5, 14, 0, tzinfo=timezone.utc)


def bundle():
    return load_bundle(ROOT / "samples" / "compliant-bundle.json")


def policy():
    return load_policy(ROOT / "policy" / "supply-chain-policy.json")


def ids(data):
    return {item.rule_id for item in analyze_bundle(data, policy(), NOW).findings}


def test_compliant_bundle_passes():
    report = analyze_bundle(bundle(), policy(), NOW)
    assert report.decision == "PASS"
    assert report.score == 100
    assert report.verified_artifacts == 2


def test_mutable_image_blocks():
    data = bundle(); data["release"]["image"] = "ghcr.io/example/service:latest"
    assert "SC001" in ids(data)


def test_missing_model_digest_blocks():
    data = bundle(); data["release"]["model"]["digest"] = ""
    assert "SC002" in ids(data)


def test_mutable_model_revision_blocks():
    data = bundle(); data["release"]["model"]["revision"] = "latest"
    assert "SC003" in ids(data)


def test_unverified_signature_blocks():
    data = bundle(); data["evidence"]["image_signature"]["verified"] = False
    assert "SC004" in ids(data)


def test_untrusted_signer_blocks():
    data = bundle(); data["evidence"]["image_signature"]["subject"] = "untrusted"
    assert "SC005" in ids(data)


def test_missing_slsa_provenance_blocks():
    data = bundle(); data["evidence"]["provenance"]["predicate_type"] = "custom"
    assert "SC006" in ids(data)


def test_untrusted_builder_blocks():
    data = bundle(); data["evidence"]["provenance"]["builder_id"] = "unknown"
    assert "SC007" in ids(data)


def test_digest_mismatch_blocks():
    data = bundle(); data["evidence"]["provenance"]["artifact_digest"] = "sha256:" + "3" * 64
    assert "SC008" in ids(data)


def test_short_source_revision_reviews():
    data = bundle(); data["evidence"]["provenance"]["source_revision"] = "abc123"
    assert "SC009" in ids(data)


def test_model_attestation_mismatch_blocks():
    data = bundle(); data["evidence"]["model_attestation"]["artifact_digest"] = "sha256:" + "4" * 64
    assert "SC010" in ids(data)


def test_stale_scan_blocks():
    data = bundle(); data["evidence"]["scan"]["generated_at"] = "2026-11-01T00:00:00Z"
    assert "SC011" in ids(data)


def test_critical_vulnerability_blocks():
    data = bundle(); data["evidence"]["scan"]["critical"] = 1
    assert "SC012" in ids(data)


def test_high_vulnerability_reviews():
    data = bundle(); data["evidence"]["scan"]["high"] = 3
    assert "SC013" in ids(data)


def test_denied_license_blocks():
    data = deepcopy(bundle()); data["evidence"]["scan"]["licenses"].append("SSPL-1.0")
    assert "SC014" in ids(data)
