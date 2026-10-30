package eu.rsdsoftware.auth;
import java.util.*;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
class IdentityAndRefreshTest {
    @Test void identityIsStableAndProvidersAreNotLinkedByName() {
        var store=new InMemoryDocumentStore(); var service=new IdentityService(store);
        var google=service.login("google","issuer-google","alice","Alice");
        assertEquals(google,service.login("google","issuer-google","alice","changed name"));
        assertNotEquals(google.subject(),service.login("github","github","alice","Alice").subject());
        assertTrue(google.roles().isEmpty());
        assertThrows(IllegalArgumentException.class,()->service.login("google","issuer","","Alice"));
    }
    @Test void rolesComeOnlyFromTheTrustedIdentityRecord() {
        var store=new InMemoryDocumentStore(); var service=new IdentityService(store);
        var identity=service.login("google","issuer","alice","Alice");
        var key="auth:v1:identity:"+identity.subject(); var row=store.get(key).orElseThrow();
        var values=new HashMap<>(row.values()); values.put("roles","JOB_REPLY,ADMIN,COMPETENCE_BUILDER");
        store.replace(key,row.revision(),values);
        assertEquals(List.of("JOB_REPLY","COMPETENCE_BUILDER"),service.find(identity.subject()).orElseThrow().roles());
    }
    @Test void refreshRotationRejectsReplayAndRevokesTheWholeFamily() {
        var service=new RefreshService(new InMemoryDocumentStore());
        String original=service.create("alice"); var rotation=service.rotate(original).orElseThrow();
        assertEquals("alice",rotation.subject()); assertNotEquals(original,rotation.token());
        assertTrue(service.rotate(original).isEmpty());
        assertTrue(service.rotate(rotation.token()).isEmpty());
    }
    @Test void logoutAndInvalidTokensFailClosed() {
        var service=new RefreshService(new InMemoryDocumentStore()); String token=service.create("alice");
        service.revoke(token); assertTrue(service.rotate(token).isEmpty());
        for(String invalid:List.of("","missing","not.a-family",".".repeat(300))) assertTrue(service.rotate(invalid).isEmpty());
        assertTrue(service.rotate(null).isEmpty()); service.revoke(null); service.revoke("missing");
    }
}

