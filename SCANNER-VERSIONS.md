# Verified baseline — 30 October 2026

Spring Boot 4.1.2 supports Java 27; Boot 4.2 RC is deliberately excluded. Maven 3.10.0 stable via checked wrapper. AWS SDK 2.57.7, JaCoCo 0.8.16, SpotBugs Maven 4.10.5.0, Find Security Bugs 1.14.0, Sonar Maven 5.8.0.7211 checked against Maven Central stable metadata.
CodeQL Action 4.39.1, Trivy 0.76.1/action 0.36.0, Semgrep CE 1.183.0; setup-java 6.1.0 is SHA-pinned. Use current compatible free releases; no paid tiers/trials.

Sources: https://docs.spring.io/spring-boot/system-requirements.html ; https://repo.maven.apache.org/maven2/ ; https://github.com/actions/setup-java/releases/tag/v6.1.0
SONAR_TOKEN was supplied and a real PR analysis successfully uploaded on 30 October 2026 (run 41101244734). The project is public with key rsds-infra-auth-service. That initial quality gate failed on two CSRF-related findings; fixes are under review and no passing gate is claimed until the updated run succeeds. Coverage in that analysis was 85.7%, duplication 0%. Native secret/dependency features require actual settings readback. No unexecuted scan is claimed complete.


Native GitHub settings read back on 30 October 2026: public=true, secret_scanning=enabled, secret_scanning_push_protection=enabled, vulnerability-alerts HTTP 204 and automated-security-fixes enabled=true. No paid security tier enabled. Required branch protection is not asserted by this audit.
