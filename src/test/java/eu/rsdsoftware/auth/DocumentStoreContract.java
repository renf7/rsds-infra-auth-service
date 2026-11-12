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
    @Test void scopedWritesStayWithinServiceAndTenant() {
        var root=store(); String tenant=UUID.randomUUID().toString();
        var owner=new eu.rsdsoftware.auth.store.ScopedDocumentStore(root,"offers",tenant);
        var other=new eu.rsdsoftware.auth.store.ScopedDocumentStore(root,"competence",tenant);
        var stranger=new eu.rsdsoftware.auth.store.ScopedDocumentStore(root,"offers",tenant+":other");
        assertTrue(owner.insert("offer:1",Map.of("schema","1")));
        assertTrue(other.get("offer:1").isEmpty()); assertTrue(stranger.get("offer:1").isEmpty());
        var revision=owner.get("offer:1").orElseThrow().revision();
        assertFalse(stranger.replace("offer:1",revision,Map.of("schema","2")));
        assertTrue(owner.replace("offer:1",revision,Map.of("schema","2")));
    }
    @Test void concurrentInsertAndCasHaveExactlyOneWinner() throws Exception {
        var store=store(); String key="auth:test:"+UUID.randomUUID();
        try(var executor=java.util.concurrent.Executors.newVirtualThreadPerTaskExecutor()) {
            var inserts=new ArrayList<java.util.concurrent.Future<Boolean>>();
            for(int i=0;i<12;i++) inserts.add(executor.submit(()->store.insert(key,Map.of("schema","1"))));
            int winners=0; for(var result:inserts) if(result.get()) winners++;
            assertEquals(1,winners);
            String revision=store.get(key).orElseThrow().revision();
            var writes=new ArrayList<java.util.concurrent.Future<Boolean>>();
            for(int i=0;i<12;i++) writes.add(executor.submit(()->store.replace(key,revision,Map.of("schema","2"))));
            winners=0; for(var result:writes) if(result.get()) winners++;
            assertEquals(1,winners); assertEquals("2",store.get(key).orElseThrow().values().get("schema"));
        }
    }
}