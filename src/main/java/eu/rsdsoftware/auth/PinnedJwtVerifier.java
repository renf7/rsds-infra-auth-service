package eu.rsdsoftware.auth;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jwt.SignedJWT;
import java.security.interfaces.RSAPublicKey;
import java.time.*;
import java.util.*;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.jwt.*;

/** Resource services may use this verifier with public keys only; no signing key is needed. */
public final class PinnedJwtVerifier {
    private PinnedJwtVerifier() {}
    public static JwtDecoder decoder(java.nio.file.Path certificates,String issuer,String audience) throws Exception {
        var keys=new HashMap<String,RSAPublicKey>();
        try(var files=java.nio.file.Files.list(certificates)) {
            for(var path:files.filter(p->p.toString().endsWith(".crt")).toList()) {
                try(var input=java.nio.file.Files.newInputStream(path)) {
                    var certificate=(java.security.cert.X509Certificate)java.security.cert.CertificateFactory.getInstance("X.509").generateCertificate(input);
                    certificate.checkValidity();
                    keys.put(TokenService.fingerprint(certificate),(RSAPublicKey)certificate.getPublicKey());
                }
            }
        }
        if(keys.isEmpty()) throw new IllegalArgumentException("Public certificate trust set is empty");
        return decoder(keys,issuer,audience);
    }
    public static JwtDecoder decoder(Map<String,RSAPublicKey> trusted,String issuer,String audience) {
        var decoders=new HashMap<String,JwtDecoder>();
        trusted.forEach((id,key) -> {
            var verifier=NimbusJwtDecoder.withPublicKey(key).signatureAlgorithm(org.springframework.security.oauth2.jose.jws.SignatureAlgorithm.RS256).build();
            verifier.setJwtValidator(new DelegatingOAuth2TokenValidator<>(
                new JwtTimestampValidator(Duration.ZERO), new JwtIssuerValidator(issuer),
                new JwtClaimValidator<List<String>>("aud",aud -> aud!=null && aud.contains(audience)),
                new JwtClaimValidator<String>("sub",sub -> sub!=null && !sub.isBlank()),
                new JwtClaimValidator<String>("jti",idClaim -> idClaim!=null && !idClaim.isBlank()),
                new JwtClaimValidator<Instant>("iat",issued -> issued!=null && !issued.isAfter(Instant.now().plusSeconds(30))),
                jwt -> jwt.getExpiresAt()!=null ? OAuth2TokenValidatorResult.success():OAuth2TokenValidatorResult.failure(new OAuth2Error("invalid_token"))));
            decoders.put(id,verifier);
        });
        var pinned=Map.copyOf(decoders);
        return token -> {
            try {
                var header=SignedJWT.parse(token).getHeader();
                var verifier=pinned.get(header.getKeyID());
                if(!JWSAlgorithm.RS256.equals(header.getAlgorithm()) || verifier==null) throw new BadJwtException("Untrusted JWT key or algorithm");
                return verifier.decode(token);
            } catch(java.text.ParseException exception) { throw new BadJwtException("Invalid JWT",exception); }
        };
    }
}

