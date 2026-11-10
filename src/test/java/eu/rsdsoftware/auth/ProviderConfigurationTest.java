package eu.rsdsoftware.auth;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import java.nio.file.*;
import java.security.*;
import java.security.interfaces.ECPublicKey;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.mock.env.MockEnvironment;
import static org.junit.jupiter.api.Assertions.*;

class ProviderConfigurationTest {
    @TempDir Path directory;
    MockEnvironment configured() {
        var env=new MockEnvironment().withProperty("rsds.auth.public-base-url","https://www.rsdsoftware.eu");
        for(String id:ProviderRegistrations.PROVIDERS) {
            env.withProperty("rsds.auth.providers."+id+".client-id",id+"-test-registration");
            env.withProperty("rsds.auth.providers."+id+".client-secret","unused-test-registration");
        }
        env.withProperty("rsds.auth.providers.microsoft.tenant","00000000-0000-0000-0000-000000000001");
        env.withProperty("rsds.auth.providers.facebook.graph-version","v25.0");
        return env;
    }
    @Test void productionRegistrationsUseProviderTlsEndpointsAndExactCallbackPaths() {
        var registrations=new ProviderRegistrations(TestSigningMaterial.settings(false),configured());
        for(String id:ProviderRegistrations.PROVIDERS) {
            var client=registrations.findByRegistrationId(id); assertNotNull(client);
            assertEquals("https://www.rsdsoftware.eu/api/auth/login/oauth2/code/"+id,client.getRedirectUri());
            assertTrue(client.getProviderDetails().getAuthorizationUri().startsWith("https://"));
            assertTrue(client.getProviderDetails().getTokenUri().startsWith("https://"));
            assertFalse(client.getScopes().contains("email"));
            assertFalse(client.getScopes().contains("user:email"));
            assertFalse(client.getProviderDetails().getUserInfoEndpoint().getUri()!=null
                && client.getProviderDetails().getUserInfoEndpoint().getUri().contains("fields=id,name,email"));
        }
        assertEquals(5,registrations.availability().size()); assertTrue(registrations.iterator().hasNext());
    }
    @Test void missingRegistrationsStayDisabledAndUnsafeTenantVersionFailClosed() {
        var empty=new ProviderRegistrations(TestSigningMaterial.settings(false),new MockEnvironment());
        assertNull(empty.findByRegistrationId("google")); assertFalse(empty.iterator().hasNext());
        assertTrue(empty.availability().stream().allMatch(v -> Boolean.FALSE.equals(v.get("enabled"))));
        assertThrows(IllegalArgumentException.class,()->new ProviderRegistrations(TestSigningMaterial.settings(false),configured().withProperty("rsds.auth.providers.microsoft.tenant","common")));
        assertThrows(IllegalArgumentException.class,()->new ProviderRegistrations(TestSigningMaterial.settings(false),configured().withProperty("rsds.auth.providers.facebook.graph-version","https://attacker.invalid")));
    }
    @Test void appleClientSecretIsShortLivedAndSignedWithTheMountedEcKey() throws Exception {
        var pair=KeyPairGenerator.getInstance("EC"); pair.initialize(256); var key=pair.generateKeyPair();
        Path privateFile=directory.resolve("apple.p8");
        Files.writeString(privateFile,"-----BEGIN PRIVATE KEY-----\n"+Base64.getMimeEncoder().encodeToString(key.getPrivate().getEncoded())+"\n-----END PRIVATE KEY-----\n");
        var env=configured().withProperty("rsds.auth.providers.apple.private-key-file",privateFile.toString())
            .withProperty("rsds.auth.providers.apple.team-id","LOCALTEST01").withProperty("rsds.auth.providers.apple.key-id","LOCALKEY01");
        var token=SignedJWT.parse(new AppleClientSecret(env).create());
        assertTrue(token.verify(new ECDSAVerifier((ECPublicKey)key.getPublic())));
        assertEquals("LOCALTEST01",token.getJWTClaimsSet().getIssuer());
        assertEquals(List.of("https://appleid.apple.com"),token.getJWTClaimsSet().getAudience());
        assertEquals(300,(token.getJWTClaimsSet().getExpirationTime().getTime()-token.getJWTClaimsSet().getIssueTime().getTime())/1000);

        assertThrows(IllegalStateException.class,()->new AppleClientSecret(new MockEnvironment()).create());
    }
}
