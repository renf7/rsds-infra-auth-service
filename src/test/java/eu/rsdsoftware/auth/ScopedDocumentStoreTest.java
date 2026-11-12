package eu.rsdsoftware.auth;
import eu.rsdsoftware.auth.store.*;
import java.util.Map;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class ScopedDocumentStoreTest {
    @Test void invalidScopesAndLogicalKeysFailBeforeStorageAccess() {
        var root=new InMemoryDocumentStore();
        assertThrows(NullPointerException.class,()->new ScopedDocumentStore(null,"auth","tenant"));
        assertThrows(NullPointerException.class,()->new ScopedDocumentStore(root,null,"tenant"));
        for(String value:new String[]{"", " ", "x".repeat(257), "\ud800"}) {
            assertThrows(IllegalArgumentException.class,()->new ScopedDocumentStore(root,value,"tenant"));
            assertThrows(IllegalArgumentException.class,()->new ScopedDocumentStore(root,"auth",value));
            var scoped=new ScopedDocumentStore(root,"auth","tenant");
            assertThrows(IllegalArgumentException.class,()->scoped.get(value));
        }
    }
    @Test void serviceAndTenantBoundariesCannotCollideOrCrossWrite() {
        var root=new InMemoryDocumentStore();
        var owner=new ScopedDocumentStore(root,"offers","tenant:a");
        var other=new ScopedDocumentStore(root,"offers","tenant:b");
        var service=new ScopedDocumentStore(root,"competence","tenant:a");
        assertTrue(owner.insert("item:1",Map.of("schema","1","owner","alice")));
        assertTrue(other.get("item:1").isEmpty());
        assertTrue(service.get("item:1").isEmpty());
        String revision=owner.get("item:1").orElseThrow().revision();
        assertFalse(other.replace("item:1",revision,Map.of("owner","mallory")));
        assertEquals("alice",owner.get("item:1").orElseThrow().values().get("owner"));
    }
    @Test void delimiterAndUnicodeInputsHaveUnambiguousFraming() {
        var root=new InMemoryDocumentStore();
        var first=new ScopedDocumentStore(root,"a:b","c");
        var second=new ScopedDocumentStore(root,"a","b:c");
        assertTrue(first.insert("żółć:1",Map.of("value","first")));
        assertTrue(second.insert("żółć:1",Map.of("value","second")));
        assertEquals("first",first.get("żółć:1").orElseThrow().values().get("value"));
    }
}
