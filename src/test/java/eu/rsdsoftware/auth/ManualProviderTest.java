package eu.rsdsoftware.auth;
import org.junit.jupiter.api.Test;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.mock.web.MockHttpServletRequest;
import static org.junit.jupiter.api.Assertions.*;
class ManualProviderTest {
    private AuthSettings live() {
        var s=TestSigningMaterial.settings(true);
        return new AuthSettings(true,s.issuer(),s.audience(),s.privateKey(),s.publicCertificates(),s.region(),s.table(),s.dynamoEndpoint(),s.idpBase(),"live");
    }
    @Test void localInfrastructureCanUseRealGitHubWithoutTheFixture() {
        var env=new MockEnvironment().withProperty("rsds.auth.public-base-url","http://127.0.0.1:18092")
            .withProperty("rsds.auth.providers.github.client-id","test-client")
            .withProperty("rsds.auth.providers.github.client-secret","test-secret")
            .withProperty("rsds.auth.providers.apple.client-id","local-apple");
        var clients=new ProviderRegistrations(live(),env);
        assertNull(clients.findByRegistrationId("apple"));
        assertNull(clients.findByRegistrationId("google"));
        var request=new MockHttpServletRequest("GET","/api/auth/oauth2/authorization/github");
        request.setServletPath("/api/auth/oauth2/authorization/github");
        var auth=new LocalizedAuthorizationResolver(clients,live()).resolve(request);
        assertEquals("https://github.com/login/oauth/authorize",auth.getAuthorizationUri());
        assertEquals("http://127.0.0.1:18092/api/auth/login/oauth2/code/github",auth.getRedirectUri());
        assertTrue(clients.findByRegistrationId("github").getScopes().contains("user:email"));
    }
    @Test void invalidModeAndProductionFixtureAreRejected() {
        assertThrows(IllegalArgumentException.class,()->new AuthSettings(false,"i","a","k","c","r","t","e","b","fixture"));
        assertThrows(IllegalArgumentException.class,()->new AuthSettings(true,"i","a","k","c","r","t","e","b","invalid"));
    }
}
