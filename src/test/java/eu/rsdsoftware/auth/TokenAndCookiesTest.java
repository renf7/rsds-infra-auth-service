package eu.rsdsoftware.auth;
import com.nimbusds.jwt.*;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.*;
import java.nio.file.*;
import java.security.*;
import java.security.spec.*;
import java.security.interfaces.RSAPrivateKey;
import java.time.Instant;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.*;
import static org.junit.jupiter.api.Assertions.*;
class TokenAndCookiesTest {
    @Test void tokensCarryTrustedClaimsAndAreVerifiedByPinnedCertificate() throws Exception {
        var service=new TokenService(TestSigningMaterial.settings(false));
        var jwt=service.decoder().decode(service.issue(new IdentityService.Identity("alice","google","Alice",List.of("JOB_REPLY"))));
        assertEquals("alice",jwt.getSubject()); assertEquals(List.of("JOB_REPLY"),jwt.getClaimAsStringList("roles"));
        assertEquals(300,jwt.getExpiresAt().getEpochSecond()-jwt.getIssuedAt().getEpochSecond());
        assertEquals(1,((List<?>)service.jwks().get("keys")).size());
    }
    @Test void invalidTokensExpiryIssuerAudienceNotBeforeAndUnknownKeysAreRejected() throws Exception {
        var service=new TokenService(TestSigningMaterial.settings(false));
        String valid=service.issue(new IdentityService.Identity("alice","google","Alice",List.of()));
        assertThrows(org.springframework.security.oauth2.jwt.JwtException.class,()->service.decoder().decode("invalid"));
        var parsed=SignedJWT.parse(valid);
        var settings=TestSigningMaterial.settings(false);
        String pem=Files.readString(Path.of(settings.privateKey())).replace("-----BEGIN PRIVATE KEY-----","").replace("-----END PRIVATE KEY-----","");
        var key=(RSAPrivateKey)KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(Base64.getMimeDecoder().decode(pem)));
        for(String invalid:List.of("expiry","issuer","audience","not-before","unknown-key")) {
            var builder=new JWTClaimsSet.Builder(parsed.getJWTClaimsSet());
            String kid=parsed.getHeader().getKeyID();
            switch(invalid) {
                case "expiry" -> builder.expirationTime(Date.from(Instant.now().minusSeconds(5)));
                case "issuer" -> builder.issuer("https://attacker.invalid");
                case "audience" -> builder.audience("another-service");
                case "not-before" -> builder.notBeforeTime(Date.from(Instant.now().plusSeconds(300)));
                case "unknown-key" -> kid="unknown";
                default -> throw new IllegalStateException();
            }
            var signed=new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(kid).build(),builder.build());
            signed.sign(new RSASSASigner(key));
            assertThrows(org.springframework.security.oauth2.jwt.JwtException.class,()->service.decoder().decode(signed.serialize()),invalid);
        }
    }
    @Test void attackerSignatureWithTheTrustedKeyIdIsRejected() throws Exception {
        var service=new TokenService(TestSigningMaterial.settings(false));
        var genuine=SignedJWT.parse(service.issue(new IdentityService.Identity("alice","google","Alice",List.of())));
        var generator=KeyPairGenerator.getInstance("RSA"); generator.initialize(2048);
        var forged=new SignedJWT(genuine.getHeader(),genuine.getJWTClaimsSet());
        forged.sign(new RSASSASigner((RSAPrivateKey)generator.generateKeyPair().getPrivate()));
        assertThrows(org.springframework.security.oauth2.jwt.JwtException.class,()->service.decoder().decode(forged.serialize()));
    }
    @Test void cookiesAreHttpOnlySecureInProductionAndScopedForRefresh() {
        var cookies=new SessionCookies(TestSigningMaterial.settings(false)); var response=new MockHttpServletResponse();
        cookies.issue(response,"test-access","test-refresh");
        var headers=response.getHeaders("Set-Cookie");
        assertEquals(2,headers.size()); assertTrue(headers.stream().allMatch(v -> v.contains("HttpOnly") && v.contains("Secure") && v.contains("SameSite=Lax")));
        assertTrue(headers.get(1).contains("Path=/api/auth"));
        cookies.clear(response); assertTrue(response.getHeaders("Set-Cookie").stream().anyMatch(v -> v.contains("Max-Age=0")));
        assertNull(SessionCookies.read(new MockHttpServletRequest(),"RSDS_ACCESS"));
    }
}

