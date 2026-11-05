# Safe deployment guide

## Adoption sequence

1. Generate the evidence bundle in CI after the container image and model artifact are finalized.
2. Verify image and model signatures with trusted identities; do not accept a producer-supplied boolean without independent verification.
3. Attach SLSA provenance and scanner results for the exact digests in the release manifest.
4. Run the guard in report-only mode and baseline existing releases before enforcing `BLOCK` decisions.
5. Protect trust roots, builders, vulnerability thresholds, and license policy with security-owner review.
6. Export the JSON report as a retained CI artifact and bind it to the Git commit and release digest.
7. Require human GitOps approval and enforce the same evidence at admission time with a suitable policy controller.

## Security and privacy

- The reference evaluator is offline and read-only. It does not pull artifacts, query registries, or contact a cluster.
- Production integrations must independently verify Cosign bundles and scanner attestations before creating the normalized input.
- Treat model registry paths, source revisions, signer identities, vulnerability findings, and license inventories as sensitive operational metadata.
- Use short-lived CI identities, least-privilege registry access, protected branches, and immutable evidence storage.
- AI may explain findings or draft remediation, but cannot alter evidence, trust roots, thresholds, approvals, or production state.

## Reliability and failure modes

- A valid signature proves control of an accepted identity, not that the artifact is safe. Provenance and scanning are separate controls.
- A fresh scanner report can still miss zero-days or model-specific unsafe behavior.
- Registry replication can delay signatures or attestations; fail closed for production and provide an auditable retry path.
- Model formats may contain executable code or custom operators. Add format-specific malware and deserialization controls before loading.
- Clock skew can incorrectly mark scans stale. Synchronize CI clocks and record evaluation time for deterministic replay.
- Trust-root rotation can invalidate otherwise legitimate releases. Use staged rollover with overlapping approved identities.

## Measurable outcomes

- Percentage of production images and models pinned by digest.
- Percentage with verified signer identity and matching provenance.
- Median age of vulnerability evidence at deployment time.
- Number and age of vulnerability or license exceptions.
- False-positive rate and median remediation time.
- Releases blocked for mismatched artifact evidence.
- Mean time to reconstruct the source and builder for an incident artifact.
