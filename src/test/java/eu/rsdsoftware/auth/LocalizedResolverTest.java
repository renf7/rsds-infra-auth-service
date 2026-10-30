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
}
