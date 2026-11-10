package eu.rsdsoftware.auth;
import com.sun.net.httpserver.HttpServer;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import static org.junit.jupiter.api.Assertions.*;
class GitHubEmailTest {
    @Test void privateEmailEndpointIsNeverRequested() throws Exception {
        check(false);
    }
    @Test void emailAvailabilityDoesNotAffectProfileLookup() throws Exception {
        check(true);
    }
    private void check(boolean incidentalEmail) throws Exception {
        var server=HttpServer.create(new InetSocketAddress("127.0.0.1",0),0);
        server.createContext("/github/",exchange->{
            if(!"Bearer fixture-access".equals(exchange.getRequestHeaders().getFirst("Authorization"))) {exchange.sendResponseHeaders(401,-1); exchange.close(); return;}
            if(exchange.getRequestURI().getPath().endsWith("/emails")) {exchange.sendResponseHeaders(500,-1); exchange.close(); return;}
            String body="{\"id\":\"123\",\"name\":\"Alice\""+(incidentalEmail?",\"email\":\"incidental@example.test\"":"")+"}";
            byte[] bytes=body.getBytes(StandardCharsets.UTF_8); exchange.getResponseHeaders().set("Content-Type","application/json");
            exchange.sendResponseHeaders(200,bytes.length); exchange.getResponseBody().write(bytes); exchange.close();
        });
        server.start();
        try {
            var base=TestSigningMaterial.settings(true);
            var settings=new AuthSettings(true,base.issuer(),base.audience(),base.privateKey(),base.publicCertificates(),base.region(),base.table(),base.dynamoEndpoint(),"http://127.0.0.1:"+server.getAddress().getPort());
            var registration=new ProviderRegistrations(settings,new MockEnvironment()).findByRegistrationId("github");
            var token=new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,"fixture-access",Instant.now(),Instant.now().plusSeconds(60),Set.of("read:user"));
            var user=new ProviderProfiles().providerUsers().loadUser(new OAuth2UserRequest(registration,token));
            assertNull(user.getAttribute("app_verified_email"));
            var profile=ProviderProfiles.read(new org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken(user,user.getAuthorities(),"github"));
            assertNull(profile.email()); assertFalse(profile.verified()); assertEquals("123",profile.externalSubject());
        } finally {server.stop(0);}
    }
}
