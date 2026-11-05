# Day 22 deployment, learning, and interview summary

Hello Jeffrey,

Day 22 is AI Model Supply Chain Guard, a production security project that evaluates the serving image and model artifact as one release unit.

## Problem and design

The project prevents a signed container from creating false confidence when the model revision is mutable, the provenance does not match the deployment digest, the builder is untrusted, or the vulnerability report is stale. It evaluates normalized evidence deterministically and reserves production authority for human GitOps approval.

## Deployment

Generate evidence after both artifacts are finalized. Independently verify signatures and attestations, bind them to exact digests, retain reports, start report-only, protect trust policy, and enforce the same decision at admission time. Handle registry or transparency-log outages with fail-closed production behavior and auditable retries.

## Learning and operational value

The project demonstrates why a valid signature is only one control. Provenance, builder identity, model checksums, vulnerability freshness, and license policy address different failure modes. Useful measures include digest-pinning and provenance coverage, evidence age, exceptions, false positives, remediation time, blocked mismatches, and incident artifact-reconstruction time.

## Interview positioning

Lead with the insight that AI releases contain two independently mutable artifacts. Discuss why the container and model must be correlated, why the reference engine does not pretend a producer-supplied `verified` flag is cryptographic proof, how trust-root rotation and scanner outages affect reliability, and why AI is limited to explanation. This demonstrates DevSecOps, Kubernetes release controls, Sigstore/in-toto concepts, SLSA, policy-as-code, CI/CD, model governance, and production failure-mode thinking.

Repository: https://github.com/ohjeffkuston/ai-model-supply-chain-guard

Regards,
Jeffrey Ikuoyemwen
