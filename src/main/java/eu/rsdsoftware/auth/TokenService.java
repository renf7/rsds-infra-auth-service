package eu.rsdsoftware.auth;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.*;
import com.nimbusds.jose.jwk.*;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.*;
import java.nio.file.*;
import java.security.*;
import java.security.cert.*;
import java.security.interfaces.*;
import java.time.*;
import java.util.*;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.stereotype.Service;

@Service
public final class TokenService {
    private final RSAKey signing;
    private final Map<String,RSAPublicKey> trusted;
    private final AuthSettings settings;
    private final JwtDecoder decoder;
    public TokenService(AuthSettings settings) throws Exception {
        this.settings=settings;
        String pem=Files.readString(Path.of(settings.privateKey()));
        byte[] der=Base64.getMimeDecoder().decode(pem.replace("-----BEGIN PRIVATE KEY-----","").replace("-----END PRIVATE KEY-----",""));
        var privateKey=(RSAPrivateKey)KeyFactory.getInstance("RSA").generatePrivate(new java.security.spec.PKCS8EncodedKeySpec(der));
        Arrays.fill(der,(byte)0);
        var publicKeys=new HashMap<String,RSAPublicKey>();
        try(var files=Files.list(Path.of(settings.publicCertificates()))) {
            for(Path path:files.filter(p -> p.toString().endsWith(".crt")).toList()) {
                try(var input=Files.newInputStream(path)) {
                    var cert=(X509Certificate)CertificateFactory.getInstance("X.509").generateCertificate(input);
                    cert.checkValidity();
                    publicKeys.put(fingerprint(cert),(RSAPublicKey)cert.getPublicKey());
                }
            }
        }
        var active=publicKeys.entrySet().stream().filter(e -> e.getValue().getModulus().equals(privateKey.getModulus())).findFirst()
            .orElseThrow(() -> new IllegalStateException("Signing key is not in the pinned certificate bundle"));
        this.signing=new RSAKey.Builder(active.getValue()).privateKey(privateKey).keyID(active.getKey()).build();
        this.trusted=Map.copyOf(publicKeys);
        this.decoder=PinnedJwtVerifier.decoder(trusted,settings.issuer(),settings.audience());
    }
    public static String fingerprint(X509Certificate certificate) throws CertificateEncodingException,NoSuchAlgorithmException {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(certificate.getEncoded()));
    }
    public String issue(IdentityService.Identity identity) {
        try {
            var now=Instant.now();
            var claims=new JWTClaimsSet.Builder().issuer(settings.issuer()).audience(settings.audience()).subject(identity.subject())
                .issueTime(Date.from(now)).expirationTime(Date.from(now.plusSeconds(300))).jwtID(UUID.randomUUID().toString())
                .claim("roles",identity.roles()).build();
            var jwt=new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(signing.getKeyID()).type(JOSEObjectType.JWT).build(),claims);
            jwt.sign(new RSASSASigner(signing)); return jwt.serialize();
        } catch(JOSEException exception) { throw new IllegalStateException("Token signing failed",exception); }
    }
    public JwtDecoder decoder() { return decoder; }
    public Map<String,Object> jwks() {
        return Map.of("keys",trusted.entrySet().stream().map(e -> new RSAKey.Builder(e.getValue()).keyID(e.getKey()).build().toJSONObject()).toList());
    }
}

