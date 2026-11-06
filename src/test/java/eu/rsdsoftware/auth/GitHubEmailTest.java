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
    @Test void privateVerifiedPrimaryEmailIsLoadedWithTheActualProviderAccessToken() throws Exception {
        check("[{\"email\":\"private@example.test\",\"primary\":true,\"verified\":true}]",true);
    }
    @Test void unverifiedEmailAndMissingPrimaryDoNotGainVerification() throws Exception {
        check("[{\"email\":\"private@example.test\",\"primary\":true,\"verified\":false}]",false);
        check("[]",false);
    }
    private void check(String emails,boolean expected) throws Exception {
        var server=HttpServer.create(new InetSocketAddress("127.0.0.1",0),0);
        server.createContext("/github/",exchange->{
            if(!"Bearer fixture-access".equals(exchange.getRequestHeaders().getFirst("Authorization"))) {exchange.sendResponseHeaders(401,-1); exchange.close(); return;}
            String body=exchange.getRequestURI().getPath().endsWith("/emails")?emails:"{\"id\":\"123\",\"name\":\"Alice\"}";
            byte[] bytes=body.getBytes(StandardCharsets.UTF_8); exchange.getResponseHeaders().set("Content-Type","application/json");
            exchange.sendResponseHeaders(200,bytes.length); exchange.getResponseBody().write(bytes); exchange.close();
        });
        server.start();
        try {
            var base=TestSigningMaterial.settings(true);
            var settings=new AuthSettings(true,base.issuer(),base.audience(),base.privateKey(),base.publicCertificates(),base.region(),base.table(),base.dynamoEndpoint(),"http://127.0.0.1:"+server.getAddress().getPort());
            var registration=new ProviderRegistrations(settings,new MockEnvironment()).findByRegistrationId("github");
            var token=new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,"fixture-access",Instant.now(),Instant.now().plusSeconds(60),Set.of("read:user","user:email"));
            var user=new ProviderProfiles().providerUsers(settings).loadUser(new OAuth2UserRequest(registration,token));
            assertEquals(expected,user.getAttribute("app_verified_email"));
            if(expected) assertEquals("private@example.test",user.getAttribute("email"));
        } finally {server.stop(0);}
    }
}
