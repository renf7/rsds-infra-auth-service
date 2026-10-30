package eu.rsdsoftware.auth;
import eu.rsdsoftware.auth.store.DocumentStore;
import java.util.*;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
abstract class DocumentStoreContract {
    abstract DocumentStore store();
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

