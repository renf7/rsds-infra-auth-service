package eu.rsdsoftware.auth;
import org.junit.jupiter.api.Test;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.mock.web.MockHttpServletRequest;
import static org.junit.jupiter.api.Assertions.*;
class LocalizedResolverTest {
    @Test void preservesOnlyFixedLanguageChoicesAndDoesNotAcceptReturnUrls() {
        var settings=TestSigningMaterial.settings(true);
        var resolver=new LocalizedAuthorizationResolver(new ProviderRegistrations(settings,new MockEnvironment()),settings);
        var request=new MockHttpServletRequest("GET","/api/auth/oauth2/authorization/google");
        request.setServletPath("/api/auth/oauth2/authorization/google");
        request.addParameter("lang","pl");
        assertNotNull(resolver.resolve(request)); assertTrue(LocalizedAuthorizationResolver.polishReturn(request));
        request.setParameter("lang","https://attacker.invalid");
        assertNotNull(resolver.resolve(request,"google")); assertFalse(LocalizedAuthorizationResolver.polishReturn(request));
        var unrelated=new MockHttpServletRequest("GET","/unrelated"); unrelated.setServletPath("/unrelated");
        assertNull(resolver.resolve(unrelated)); assertNull(unrelated.getSession(false));
        assertFalse(LocalizedAuthorizationResolver.polishReturn(unrelated));
    }
    @Test void oidcRequestsUseFreshStateNonceAndS256WithoutAcceptingRedirectOverride() {
        var settings=TestSigningMaterial.settings(true);
        var resolver=new LocalizedAuthorizationResolver(new ProviderRegistrations(settings,new MockEnvironment()),settings);
        var request=new MockHttpServletRequest("GET","/api/auth/oauth2/authorization/google");
        request.setScheme("http"); request.setServerName("localhost"); request.setServerPort(8080);
        request.setServletPath("/api/auth/oauth2/authorization/google");
        request.addParameter("redirect_uri","https://attacker.invalid/callback");
        request.addParameter("state","attacker-state"); request.addParameter("nonce","attacker-nonce");
        var first=resolver.resolve(request); var second=resolver.resolve(request);
        assertNotNull(first); assertNotNull(second);
        assertNotEquals("attacker-state",first.getState()); assertNotEquals(first.getState(),second.getState());
        assertNotEquals("attacker-nonce",first.getAdditionalParameters().get("nonce"));
        assertNotEquals(first.getAdditionalParameters().get("nonce"),second.getAdditionalParameters().get("nonce"));
        assertEquals("S256",first.getAdditionalParameters().get("code_challenge_method"));
        assertNotNull(first.getAdditionalParameters().get("code_challenge"));
        assertEquals("http://localhost:8080/api/auth/login/oauth2/code/google",first.getRedirectUri());
    }}
