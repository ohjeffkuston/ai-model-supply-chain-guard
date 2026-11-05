Imagine a production inference service running a signed container image while silently loading a mutable model revision that nobody can trace back to its source.

That gap matters because AI releases combine containers, model weights, build systems, registries, scanners, and deployment pipelines. A compromise or accidental overwrite in any one of them can undermine incident response, reproducibility, and customer trust.

The security issue is evidence fragmentation: signatures may not match the deployed digest, provenance may name an untrusted builder, scan results may be stale, and the model itself may have no immutable checksum.

I built AI Model Supply Chain Guard to evaluate the whole release as one deterministic GitOps decision.

- Requires digest-pinned container images and immutable model revisions
- Verifies trusted signer identity and SLSA provenance against the deployed digest
- Matches model attestations to the exact model checksum
- Enforces vulnerability freshness, severity thresholds, and license policy
- Keeps AI advisory-only while deterministic policy and human approval control production

The game-changing part is treating the model and serving image as one auditable release unit instead of assuming container security automatically covers the AI artifact.

Architecture and implementation: https://github.com/ohjeffkuston/ai-model-supply-chain-guard

How does your organization prove that the exact model running in production came from the reviewed source and approved builder?

#AIInfrastructure #SoftwareSupplyChain #Kubernetes #DevSecOps #PlatformEngineering
