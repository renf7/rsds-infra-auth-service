package eu.rsdsoftware.auth;
import org.springframework.boot.context.properties.ConfigurationProperties;
@ConfigurationProperties("rsds.auth")
public record AuthSettings(boolean local, String issuer, String audience, String privateKey,
                           String publicCertificates, String region, String table, String dynamoEndpoint, String idpBase) {}

