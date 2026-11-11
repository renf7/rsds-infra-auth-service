package eu.rsdsoftware.auth;
import java.time.*;
import java.util.*;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class RetentionTest {
    @Test void refreshRotationAndRevocationKeepBoundedEvidence() {
        var store=new InMemoryDocumentStore();
        Instant now=Instant.parse("2030-01-01T00:00:00Z");
        var service=new RefreshService(store,Clock.fixed(now,ZoneOffset.UTC),86400);
        String token=service.create("alice"),key="auth:v1:refresh:"+token.substring(0,token.indexOf('.'));
        var deadline=now.plusSeconds(604800+86400);
        assertEquals(deadline,store.get(key).orElseThrow().deleteAfter());
        var rotated=service.rotate(token).orElseThrow();
        assertEquals(deadline,store.get(key).orElseThrow().deleteAfter());
        assertTrue(service.rotate(token).isEmpty()); // Replay revokes the whole family.
        assertTrue(service.rotate(rotated.token()).isEmpty());
        assertEquals(deadline,store.get(key).orElseThrow().deleteAfter());
        var expired=new RefreshService(store,Clock.fixed(now.plusSeconds(604800),ZoneOffset.UTC),86400);
        assertTrue(expired.rotate(rotated.token()).isEmpty()); // Physical TTL deletion is not authorization.
        service.revoke(rotated.token());
        assertEquals(deadline,store.get(key).orElseThrow().deleteAfter());
    }
    @Test void permanentNamespacesCannotAcquireRetention() {
        for(String key:List.of("auth:v3:account:alice","auth:v2:binding:alice","offers:alice","auth:v1:identity:alice"))
            assertThrows(IllegalArgumentException.class,()->TransientRetention.deadline(key,Map.of("expires","123"),86400));
        assertEquals(Instant.ofEpochSecond(86523),TransientRetention.deadline("auth:v2:mail-window:hash",Map.of("until","123"),86400));
    }
}
