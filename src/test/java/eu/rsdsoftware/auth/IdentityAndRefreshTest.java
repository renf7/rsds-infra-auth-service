package eu.rsdsoftware.auth;
import java.util.*;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
class IdentityAndRefreshTest {
    @Test void identityIsStableAndProvidersAreNotLinkedByName() {
        var store=new InMemoryDocumentStore(); var service=new IdentityService(store);
        var google=service.login("google","issuer-google","alice","Alice","alice@example.test",true);
        assertEquals(google,service.login("google","issuer-google","alice","changed name","alice@example.test",true));
        assertNotEquals(google.subject(),service.login("github","github","alice","Alice","alice@example.test",true).subject());
        assertTrue(google.roles().isEmpty());
        assertThrows(IllegalArgumentException.class,()->service.login("google","issuer","","Alice","alice@example.test",true));
    }
    @Test void rolesComeOnlyFromTheTrustedIdentityRecord() {
        var store=new InMemoryDocumentStore(); var service=new IdentityService(store);
        var identity=service.login("google","issuer","alice","Alice","alice@example.test",true);
        var key=store.get("auth:v2:account:"+identity.subject()).orElseThrow().values().get("emailKey"); var row=store.get(key).orElseThrow();
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
    @Test void expiredAndMissingRefreshFamiliesCannotBeUsed() {
        var store=new InMemoryDocumentStore(); var service=new RefreshService(store);
        String token=service.create("alice"), key="auth:v1:refresh:"+token.substring(0,token.indexOf('.'));
        var row=store.get(key).orElseThrow(); var expired=new HashMap<>(row.values()); expired.put("expires","1");
        store.replace(key,row.revision(),expired); assertTrue(service.rotate(token).isEmpty());
        String missing=UUID.randomUUID()+".random"; assertTrue(service.rotate(missing).isEmpty()); service.revoke(missing);
    }
}

