# Auth repository hardening (RSDSINFRA-34)

## Trust boundaries

Maven verify and dependency collection run in an unprivileged job without SONAR_TOKEN.
Only classes, coverage and dependency jars pass to a fresh scanner job. The scanner
job never runs Maven, repository Python or shell scripts. It uses fixed workflow
scanner properties and a SHA-pinned scanner action. Token availability is restricted
to the public-project verification and scan steps. Forks never receive it. Workflow
changes themselves remain security-sensitive: CODEOWNERS/review is required; step
environment scoping alone does not make a malicious workflow safe.

## Repository administrator prerequisite

The GitHub connector returned 403 for branch protection. CODEOWNERS alone does not
require approvals. On main, enable required PRs, code-owner review, dismissal of stale
approvals, approval after the last push, conversation resolution, and strict required
checks: verify, build, analyze (Sonar), image, Dependency vulnerability scan, semgrep,
and CodeQL Actions/Java checks (select exact contexts from a completed run).
Preserve existing rules and do not enable a paid feature/trial. Use public-repository
GitHub Free branch protection. Add an independent collaborator with write access to
CODEOWNERS if renf7 authors the PR; authors cannot approve their own PR. No bypass
or self-approval claim is made. Review CODEOWNERS itself under the same rule.

## Regression coverage

TokenAndCookiesTest covers issuer, audience, expiry, unknown kid and now a foreign
RSA signature with the *correct* trusted kid. LocalizedResolverTest checks fresh
state/nonce, S256 PKCE and rejection of browser redirect overrides. ApiSecurityTest
rejects forged callback state, including Apple POST. ProviderIdentityPolicyTest
checks convergence by provider+issuer+immutable subject and separation by changed
issuer/subject regardless of email. rsds-infra-local fixtures exercise full callback,
nonce/signature/token flow without claiming real-provider acceptance.

## Main image evidence

Publishing stays main-only. BuildKit generates minimal provenance and an SPDX SBOM;
the containerd image store preserves them while the exact loaded image is scanned
before Docker Hub login/push. The main job verifies registry attestation manifests
and saves index/provenance/SBOM JSON as seven-day workflow artifacts. Failure to find
attestations fails publishing evidence collection. No GitHub attestation service,
OIDC grant, paid Docker Scout plan or new signing secret is required. This is build
metadata, not a cryptographic identity signature; do not claim signed provenance.

Consumers should resolve the git-SHA tag to its digest and inspect that immutable
reference, not latest:

```bash
docker buildx imagetools inspect renf7/rsds-infra-auth-service@sha256:YOUR_DIGEST
docker buildx imagetools inspect renf7/rsds-infra-auth-service@sha256:YOUR_DIGEST --format '{{ json .Provenance.SLSA }}'
docker buildx imagetools inspect renf7/rsds-infra-auth-service@sha256:YOUR_DIGEST --format '{{ json .SBOM.SPDX }}'
```

A real trusted-main publishing run is required to establish Docker Hub preservation;
PR checks do not publish. This remains a post-merge acceptance item, not a passing
claim based only on workflow YAML.

Official references:
- https://docs.docker.com/build/ci/github-actions/attestations/
- https://docs.docker.com/build/metadata/attestations/
- https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations
