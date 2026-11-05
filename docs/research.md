# Demand and source validation

Checked 2026-11-05 (America/Detroit).

## Authoritative technical sources

- Kubernetes documents that tags are mutable while image digests uniquely identify immutable image content: https://kubernetes.io/docs/concepts/containers/images/
- Sigstore documents Cosign signature verification for container images: https://docs.sigstore.dev/cosign/verifying/verify/
- Sigstore documents signed in-toto attestations and policy validation: https://docs.sigstore.dev/cosign/verifying/attestation/
- SLSA defines provenance as verifiable information describing where, when, and how an artifact was produced: https://slsa.dev/spec/v1.2/provenance

## Current role evidence

- AI infrastructure security: remote role, $240K-$290K, explicitly covers Kubernetes security, software supply chain, artifact signing, provenance, and admission controls for model-serving infrastructure: https://jobs.ashbyhq.com/runway-ml/0c750d2f-f894-4c8d-8b47-f03ddbb794a6/
- AI/ML platform engineering: remote U.S. role, $136K-$240K, requires production Kubernetes, Terraform, CI/CD, and developer tooling: https://jobs.ashbyhq.com/Deepgram/f424ef6a-c27f-4984-9e77-40a1ad16ae28
- Kubernetes and AI application security: remote U.S./Canada/EMEA role, $150K-$220K in the U.S., focused on secure Kubernetes multi-tenancy and AI infrastructure: https://jobs.ashbyhq.com/vClusterLabs/83c81a73-973f-406c-8482-64b09a968307
- Infrastructure security: remote U.S./Canada role, $175K-$275K, requires security-focused platform engineering, Kubernetes, identity, and policy controls: https://jobs.ashbyhq.com/workos/ffba59a1-cead-4231-bd2d-a24649c6a3b9

## Demand rationale

AI releases combine at least two independently mutable artifacts: the serving container and the model itself. A deployment can reference an immutable container yet still load a mutable model revision, or it can have a signed image whose provenance does not match the deployed digest. Current AI-infrastructure security roles explicitly require artifact signing, provenance, scanning, Kubernetes admission, and model-serving controls. The project therefore treats container, model, attestation, and scanner evidence as one release decision rather than a generic AI demonstration.

These postings validate the problem domain, not candidate fit or application eligibility.
