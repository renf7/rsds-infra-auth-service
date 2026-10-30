# rsds-infra-auth-service

Authentication backend for the one RSDS-INFRA frontend. Jira: [RSDSINFRA-16](https://rsdsoftware.atlassian.net/browse/RSDSINFRA-16), JWT/session RSDSINFRA-17, persistence RSDSINFRA-15, UI RSDSINFRA-19.

Baseline: Spring Boot 4.1.2, Java 27 (latest stable verified 30 October 2026), Spring Security-managed OAuth2/OIDC and JWT libraries. Public repository; free scanners only. Read [AGENTS.md](AGENTS.md) and the [repository standard](https://github.com/renf7/rsds-infra-helm/blob/main/docs/security/REPOSITORY-STANDARD.md).

The initial default branch is a compiled security/bootstrap baseline. Authentication feature work is reviewed on a dedicated PR; do not treat the bootstrap as a complete auth implementation. Provider app registrations are not supplied. Local protocol fixtures never establish live-provider acceptance.

Build with Java 27: `sh mvnw verify`. Docker build requires no host Java/Maven. The committed Maven 3.10.0 wrapper validates its distribution SHA-256 (upstream SHA-512 verified during bootstrap). Never commit signing keys/provider credentials.

All backends must use current stable Java/Spring Boot and this baseline: CodeQL, Semgrep CE, Trivy, Sonar public quality gate, dependency checks/Dependabot, secret protection, compiled SpotBugs + Find Security Bugs. Actual scan evidence and native settings must be verified, not inferred from YAML.

