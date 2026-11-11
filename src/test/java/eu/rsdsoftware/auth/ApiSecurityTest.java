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
    @Autowired EmailVerification verification;
    static final java.util.concurrent.atomic.AtomicReference<String> deliveredCode=new java.util.concurrent.atomic.AtomicReference<>();
    @org.springframework.boot.test.context.TestConfiguration
    static class MailFixture {
        @org.springframework.context.annotation.Bean @org.springframework.context.annotation.Primary
        VerificationMail capturedMail() {return (email,code)->deliveredCode.set(code);}
    }
    @DynamicPropertySource static void properties(DynamicPropertyRegistry properties) {
        var settings=TestSigningMaterial.settings(true);
        properties.add("rsds.auth.local",()->"true");
        properties.add("rsds.auth.providers.apple.enabled",()->"true"); // Isolated retained protocol tests only.
        properties.add("rsds.auth.private-key",settings::privateKey);
        properties.add("rsds.auth.public-certificates",settings::publicCertificates);
        properties.add("rsds.auth.dynamo-endpoint",()->System.getenv("TEST_DYNAMO_ENDPOINT"));
        properties.add("rsds.auth.table",()->"auth-api-tests");
    }
    HttpClient client;
    @Test void unknownRoutesAreDeniedAndAccountReadsUseValidatedSubject() throws Exception {
        var alice=identities.login("google","ownership",UUID.randomUUID().toString(),"Alice",null,false);
        var bob=identities.login("google","ownership",UUID.randomUUID().toString(),"Bob",null,false);
        String cookie="RSDS_ACCESS="+tokens.issue(alice);
        var own=get("/api/auth/me?subject="+bob.subject(),cookie);
        assertEquals(200,own.statusCode());
        assertTrue(own.body().contains(alice.subject()));assertFalse(own.body().contains(bob.subject()));
        assertTrue(Set.of(401,403).contains(get("/api/auth/unlisted",null).statusCode()));
        var denied=HttpRequest.newBuilder(URI.create("http://localhost:"+port+"/api/auth/unlisted"))
            .header("Authorization","Bearer "+tokens.issue(alice)).GET().build();
        assertEquals(403,client.send(denied,HttpResponse.BodyHandlers.ofString()).statusCode());
    }
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
    HttpResponse<String> jsonPost(String path,String flow,String csrf,String json) throws Exception {
        var request=HttpRequest.newBuilder(URI.create("http://localhost:"+port+path))
            .header("Content-Type","application/json").header("Cookie","RSDS_PENDING="+flow)
            .POST(HttpRequest.BodyPublishers.ofString(json));
        if(csrf!=null) request.header("X-XSRF-TOKEN",csrf);
        return client.send(request.build(),HttpResponse.BodyHandlers.ofString());
    }
    @Test void emailCodeMustBeDeliveredVerifiedAndConsumedBeforeJwtIssuance() throws Exception {
        String id=UUID.randomUUID().toString(), email="verify-"+id+"@example.test";
        String flow=verification.begin(new ProviderProfile("microsoft","issuer",id,"Alice",null,false));
        assertEquals(200,get("/api/auth/email-verification","RSDS_PENDING="+flow).statusCode());
        assertEquals(401,get("/api/auth/email-verification",null).statusCode());
        String body="{\"email\":\""+email+"\"}";
        assertEquals(403,jsonPost("/api/auth/email-code",flow,null,body).statusCode());
        String csrf=csrf(); assertEquals(204,jsonPost("/api/auth/email-code",flow,csrf,body).statusCode());
        assertEquals(400,jsonPost("/api/auth/email-code",flow,csrf,body).statusCode());
        assertEquals(401,get("/api/auth/me",null).statusCode());
        String correct=deliveredCode.get(), wrong="111111".equals(correct)?"222222":"111111";
        assertEquals(400,jsonPost("/api/auth/verify-email",flow,csrf,"{\"code\":\""+wrong+"\"}").statusCode());
        assertEquals(204,jsonPost("/api/auth/verify-email",flow,csrf,"{\"code\":\""+correct+"\"}").statusCode());
        assertEquals(200,get("/api/auth/me",null).statusCode());
        assertFalse(get("/api/auth/session",null).body().contains(email));
        assertEquals(400,jsonPost("/api/auth/verify-email",flow,csrf,"{\"code\":\""+correct+"\"}").statusCode());
    }
    @Test void anonymousSessionProtectedResourceAndCsrfAreEnforced() throws Exception {
        assertEquals(200,get("/api/auth/session",null).statusCode());
        assertEquals(401,get("/api/auth/me",null).statusCode());
        assertEquals(403,post("/api/auth/logout",null,null).statusCode());
        assertEquals(204,post("/api/auth/logout",null,csrf()).statusCode());
        assertEquals(200,get("/api/auth/providers",null).statusCode());
        assertEquals(200,get("/api/auth/.well-known/jwks.json",null).statusCode());
    }
    @Test void refreshCookiePresenceIsOnlyARecoveryHintAndNeverAuthenticates() throws Exception {
        var anonymous=get("/api/auth/session",null);
        assertEquals(200,anonymous.statusCode());
        assertTrue(anonymous.body().contains("\"refreshAvailable\":false"));
        var hinted=get("/api/auth/session","RSDS_REFRESH=invalid-hint-only");
        assertEquals(200,hinted.statusCode());
        assertTrue(hinted.body().contains("\"authenticated\":false"));
        assertTrue(hinted.body().contains("\"refreshAvailable\":true"));
        assertFalse(hinted.body().contains("invalid-hint-only"));
        assertEquals(401,post("/api/auth/refresh","RSDS_REFRESH=invalid-hint-only",csrf()).statusCode());
    }
    @Test void settingsRequireJwtAndCsrfAndSaveOnlyContactData() throws Exception {
        var account=identities.login("facebook","issuer",UUID.randomUUID().toString(),"No email",null,false);
        String access=tokens.issue(account);
        assertEquals(401,get("/api/auth/settings",null).statusCode());
        assertEquals(200,get("/api/auth/settings","RSDS_ACCESS="+access).statusCode());
        String csrf=csrf();
        var uri=URI.create("http://localhost:"+port+"/api/auth/settings");
        var withoutCsrf=HttpRequest.newBuilder(uri).header("Cookie","RSDS_ACCESS="+access)
            .header("Content-Type","application/json").PUT(HttpRequest.BodyPublishers.ofString("{\"email\":\"contact@example.test\"}")).build();
        assertEquals(403,client.send(withoutCsrf,HttpResponse.BodyHandlers.discarding()).statusCode());
        var save=HttpRequest.newBuilder(uri).header("Cookie","RSDS_ACCESS="+access).header("X-XSRF-TOKEN",csrf)
            .header("Content-Type","application/json").PUT(HttpRequest.BodyPublishers.ofString("{\"email\":\"contact@example.test\"}")).build();
        assertEquals(204,client.send(save,HttpResponse.BodyHandlers.discarding()).statusCode());
        assertTrue(get("/api/auth/settings","RSDS_ACCESS="+access).body().contains("contact@example.test"));
        assertEquals("",identities.find(account.subject()).orElseThrow().email());
        var invalid=HttpRequest.newBuilder(uri).header("Cookie","RSDS_ACCESS="+access).header("X-XSRF-TOKEN",csrf)
            .header("Content-Type","application/json").PUT(HttpRequest.BodyPublishers.ofString("{\"email\":\"invalid\"}")).build();
        assertEquals(400,client.send(invalid,HttpResponse.BodyHandlers.discarding()).statusCode());
    }
    @Test void signedTokenResolvesPersistedIdentityAndRefreshRotates() throws Exception {
        var identity=identities.login("github","github","api-alice","Alice","api-alice@example.test",true);
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
    @Test void applePostExceptionStillRejectsForgedStateAndDoesNotApplyToOtherMutations() throws Exception {
        get("/api/auth/oauth2/authorization/apple",null);
        var request=HttpRequest.newBuilder(URI.create("http://localhost:"+port+"/api/auth/login/oauth2/code/apple"))
            .header("Content-Type","application/x-www-form-urlencoded")
            .POST(HttpRequest.BodyPublishers.ofString("code=forged&state=invalid")).build();
        var invalid=client.send(request,HttpResponse.BodyHandlers.ofString());
        assertEquals(302,invalid.statusCode());
        assertTrue(invalid.headers().firstValue("Location").orElseThrow().contains("login=failed"));
        assertTrue(invalid.headers().allValues("Set-Cookie").stream().noneMatch(v -> v.startsWith("RSDS_ACCESS=") && !v.contains("Max-Age=0")));
        assertEquals(401,get("/api/auth/me",null).statusCode());
        assertEquals(403,post("/api/auth/refresh",null,null).statusCode());
        assertEquals(403,post("/api/auth/login/oauth2/code/google",null,null).statusCode());
        assertEquals(403,post("/api/auth/login/oauth2/code/apple/extra",null,null).statusCode());
    }
}

