package eu.rsdsoftware.auth;
import java.net.*;
import java.net.http.*;
import java.util.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.test.context.*;
import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest(webEnvironment=SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles("local")
@EnabledIfEnvironmentVariable(named="TEST_DYNAMO_ENDPOINT",matches="http://.+")
class ApiSecurityTest {
    @LocalServerPort int port;
    @Autowired TokenService tokens;
    @Autowired IdentityService identities;
    @Autowired RefreshService refresh;
    @DynamicPropertySource static void properties(DynamicPropertyRegistry properties) {
        var settings=TestSigningMaterial.settings(true);
        properties.add("rsds.auth.local",()->"true");
        properties.add("rsds.auth.private-key",settings::privateKey);
        properties.add("rsds.auth.public-certificates",settings::publicCertificates);
        properties.add("rsds.auth.dynamo-endpoint",()->System.getenv("TEST_DYNAMO_ENDPOINT"));
        properties.add("rsds.auth.table",()->"auth-api-tests");
    }
    HttpClient client;
    @BeforeEach void client() { client=HttpClient.newBuilder().cookieHandler(new CookieManager(null,CookiePolicy.ACCEPT_ALL)).followRedirects(HttpClient.Redirect.NEVER).build(); }
    HttpResponse<String> get(String path,String cookie) throws Exception {
        var request=HttpRequest.newBuilder(URI.create("http://localhost:"+port+path)).GET();
        if(cookie!=null) request.header("Cookie",cookie);
        return client.send(request.build(),HttpResponse.BodyHandlers.ofString());
    }
    HttpResponse<String> post(String path,String cookie,String csrf) throws Exception {
        var request=HttpRequest.newBuilder(URI.create("http://localhost:"+port+path)).POST(HttpRequest.BodyPublishers.noBody());
        if(cookie!=null) request.header("Cookie",cookie); if(csrf!=null) request.header("X-XSRF-TOKEN",csrf);
        return client.send(request.build(),HttpResponse.BodyHandlers.ofString());
    }
    String csrf() throws Exception {
        var response=get("/api/auth/csrf",null); assertEquals(200,response.statusCode());
        return new tools.jackson.databind.json.JsonMapper().readTree(response.body()).get("token").asString();
    }
    @Test void anonymousSessionProtectedResourceAndCsrfAreEnforced() throws Exception {
        assertEquals(200,get("/api/auth/session",null).statusCode());
        assertEquals(401,get("/api/auth/me",null).statusCode());
        assertEquals(403,post("/api/auth/logout",null,null).statusCode());
        assertEquals(204,post("/api/auth/logout",null,csrf()).statusCode());
        assertEquals(200,get("/api/auth/providers",null).statusCode());
        assertEquals(200,get("/api/auth/.well-known/jwks.json",null).statusCode());
    }
    @Test void signedTokenResolvesPersistedIdentityAndRefreshRotates() throws Exception {
        var identity=identities.login("github","github","api-alice","Alice");
        String access=tokens.issue(identity);
        assertEquals(200,get("/api/auth/me","RSDS_ACCESS="+access).statusCode());
        assertTrue(get("/api/auth/session","RSDS_ACCESS="+access).body().contains("\"authenticated\":true"));
        assertEquals(401,get("/api/auth/me","RSDS_ACCESS=forged").statusCode());
        String csrf=csrf();
        String token=refresh.create(identity.subject());
        assertEquals(204,post("/api/auth/refresh","RSDS_REFRESH="+token,csrf).statusCode());
        var cookieStore=((CookieManager)client.cookieHandler().orElseThrow()).getCookieStore();
        for(var cookie:List.copyOf(cookieStore.getCookies())) if(cookie.getName().equals("RSDS_REFRESH")) cookieStore.remove(null,cookie);
        assertEquals(401,post("/api/auth/refresh","RSDS_REFRESH="+token,csrf).statusCode());
        assertEquals(401,post("/api/auth/refresh",null,csrf).statusCode());
    }
    @Test void providerAuthorizationRequiresStateAndOidcNonceWithoutExposingCredentials() throws Exception {
        for(String provider:ProviderRegistrations.PROVIDERS) {
            var response=get("/api/auth/oauth2/authorization/"+provider,null);
            assertEquals(302,response.statusCode());
            String location=response.headers().firstValue("Location").orElseThrow();
            assertTrue(location.contains("state=")); assertFalse(location.contains("client_secret"));
            if(Set.of("google","microsoft","apple").contains(provider)) assertTrue(location.contains("nonce="));
            if(Set.of("google","microsoft","github").contains(provider)) assertTrue(location.contains("code_challenge="));
            if(provider.equals("apple")) assertTrue(location.contains("form_post"));
        }
        var invalid=get("/api/auth/login/oauth2/code/google?code=forged&state=invalid",null);
        assertEquals(302,invalid.statusCode());
        assertTrue(invalid.headers().firstValue("Location").orElseThrow().contains("login=failed"));
        assertTrue(invalid.headers().allValues("Set-Cookie").stream().noneMatch(v -> v.startsWith("RSDS_ACCESS=") && !v.contains("Max-Age=0")));
    }
}

