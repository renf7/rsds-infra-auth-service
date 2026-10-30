package eu.rsdsoftware.auth;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jwt.*;
import java.nio.file.*;
import java.time.Instant;
import java.util.Date;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;
@Component
public final class AppleClientSecret {
    private final Environment env;
    private final AuthSettings settings;
    public AppleClientSecret(Environment env,AuthSettings settings) { this.env=env; this.settings=settings; }
    public String create() {
        if(settings.local()) return "local-fixture-secret";
        try {
            String prefix="rsds.auth.providers.apple.";
            String pem=Files.readString(Path.of(env.getRequiredProperty(prefix+"private-key-file")));
            byte[] der=java.util.Base64.getMimeDecoder().decode(pem.replace("-----BEGIN PRIVATE KEY-----","").replace("-----END PRIVATE KEY-----",""));
            var key=(java.security.interfaces.ECPrivateKey)java.security.KeyFactory.getInstance("EC").generatePrivate(new java.security.spec.PKCS8EncodedKeySpec(der));
            var now=Instant.now();
            var token=new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.ES256).keyID(env.getRequiredProperty(prefix+"key-id")).build(),
                new JWTClaimsSet.Builder().issuer(env.getRequiredProperty(prefix+"team-id")).subject(env.getRequiredProperty(prefix+"client-id"))
                .audience("https://appleid.apple.com").issueTime(Date.from(now)).expirationTime(Date.from(now.plusSeconds(300))).build());
            token.sign(new ECDSASigner(key)); return token.serialize();
        } catch(Exception exception) { throw new IllegalStateException("Apple client authentication failed",exception); }
    }
}

