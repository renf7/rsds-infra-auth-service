package eu.rsdsoftware.auth;

import org.junit.jupiter.api.Test;
import org.springframework.mock.env.MockEnvironment;
import static org.junit.jupiter.api.Assertions.*;

class DeferredAppleTest {
    @Test void productionAppleStaysDisabledEvenWithStaleCredentials() {
        var env=new MockEnvironment().withProperty("rsds.auth.public-base-url","https://www.rsdsoftware.eu")
            .withProperty("rsds.auth.providers.apple.client-id","stale-services-id");
        var registrations=new ProviderRegistrations(TestSigningMaterial.settings(false),env);
        assertNull(registrations.findByRegistrationId("apple"));
        assertTrue(registrations.availability().stream().anyMatch(item->"apple".equals(item.get("id")) && Boolean.FALSE.equals(item.get("enabled"))));
    }
    @Test void normalFixtureStackAlsoKeepsAppleDisabled() {
        var settings=TestSigningMaterial.settings(true);
        var registrations=new ProviderRegistrations(settings,new MockEnvironment());
        assertNull(registrations.findByRegistrationId("apple"));
        assertNotNull(registrations.findByRegistrationId("google"));
        assertNotNull(registrations.findByRegistrationId("github"));
        var request=new org.springframework.mock.web.MockHttpServletRequest("GET","/api/auth/oauth2/authorization/apple");
        request.setServletPath("/api/auth/oauth2/authorization/apple");
        var resolver=new LocalizedAuthorizationResolver(registrations,settings);
        assertNull(resolver.resolve(request));
        assertNull(resolver.resolve(request,"apple"));
        assertNull(request.getSession(false));
    }
    @Test void isolatedProtocolTestsCanExplicitlyEnableRetainedImplementation() {
        var registrations=new ProviderRegistrations(TestSigningMaterial.settings(true),new MockEnvironment()
            .withProperty("rsds.auth.providers.apple.enabled","true"));
        assertNotNull(registrations.findByRegistrationId("apple"));
    }
}
