# Verified baseline — 30 October 2026

Spring Boot 4.1.2 supports Java 27; Boot 4.2 RC is deliberately excluded. Maven 3.10.0 stable via checked wrapper. AWS SDK 2.57.7, JaCoCo 0.8.16, SpotBugs Maven 4.10.5.0, Find Security Bugs 1.14.0, Sonar Maven 5.8.0.7211 checked against Maven Central stable metadata.
CodeQL Action 4.39.1, Trivy 0.76.1/action 0.36.0, Semgrep CE 1.183.0; setup-java 6.1.0 is SHA-pinned. Use current compatible free releases; no paid tiers/trials.

Sources: https://docs.spring.io/spring-boot/system-requirements.html ; https://repo.maven.apache.org/maven2/ ; https://github.com/actions/setup-java/releases/tag/v6.1.0
SONAR_TOKEN must be added to this new repository before real gate verification. Native secret/dependency features require actual settings readback. No unexecuted scan is claimed complete.

