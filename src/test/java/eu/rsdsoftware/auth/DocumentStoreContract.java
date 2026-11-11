package eu.rsdsoftware.auth;
import eu.rsdsoftware.auth.store.DocumentStore;
import java.util.*;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
abstract class DocumentStoreContract {
    abstract DocumentStore store();
    @Test void retentionMetadataSurvivesAtomicUpdatesAndPermanentRowsOmitIt() {
        var store=store(); String key="auth:v1:refresh:"+UUID.randomUUID();
        var expiry=java.time.Instant.now().plusSeconds(90000).truncatedTo(java.time.temporal.ChronoUnit.SECONDS);
        var values=Map.of("expires",Long.toString(expiry.minusSeconds(86400).getEpochSecond()));
        assertTrue(store.insertExpiring(key,values,expiry));
        var first=store.get(key).orElseThrow(); assertEquals(expiry,first.deleteAfter());
        assertTrue(store.replace(key,first.revision(),values));
        assertEquals(expiry,store.get(key).orElseThrow().deleteAfter());
        assertFalse(store.replaceExpiring(key,first.revision(),values,expiry.plusSeconds(1)));
        String permanent="auth:test:"+UUID.randomUUID();store.insert(permanent,Map.of());
        assertNull(store.get(permanent).orElseThrow().deleteAfter());
    }
    @Test void conditionalInsertPreservesExistingIdentity() {
        var store=store(); String key="auth:test:"+UUID.randomUUID();
        assertTrue(store.insert(key,Map.of("roles","","schema","1")));
        assertFalse(store.insert(key,Map.of("roles","ADMIN")));
        assertEquals("",store.get(key).orElseThrow().values().get("roles"));
    }
    @Test void optimisticWriteRejectsStaleVersions() {
        var store=store(); String key="auth:test:"+UUID.randomUUID();
        store.insert(key,Map.of("hash","first")); var first=store.get(key).orElseThrow();
        assertTrue(store.replace(key,first.revision(),Map.of("hash","second")));
        assertFalse(store.replace(key,first.revision(),Map.of("hash","replayed")));
        assertEquals("second",store.get(key).orElseThrow().values().get("hash"));
        assertFalse(store.replace("missing:"+UUID.randomUUID(),"missing",Map.of()));
    }
    @Test void namespacesAndSnapshotsAreIsolated() {
        var store=store(); String key="auth:test:"+UUID.randomUUID(); var values=new HashMap<>(Map.of("subject","alice"));
        store.insert(key,values); values.put("subject","mallory");
        assertEquals("alice",store.get(key).orElseThrow().values().get("subject"));
        assertTrue(store.get("offers:"+key).isEmpty());
        assertThrows(UnsupportedOperationException.class,()->store.get(key).orElseThrow().values().put("subject","other"));
    }
}

