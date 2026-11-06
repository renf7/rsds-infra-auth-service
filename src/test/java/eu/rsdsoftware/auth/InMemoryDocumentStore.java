package eu.rsdsoftware.auth;
import eu.rsdsoftware.auth.store.DocumentStore;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
final class InMemoryDocumentStore implements DocumentStore {
    private final ConcurrentHashMap<String,Snapshot> rows=new ConcurrentHashMap<>();
    public Optional<Snapshot> get(String key) { return Optional.ofNullable(rows.get(key)); }
    public boolean insert(String key,Map<String,String> values) { return rows.putIfAbsent(key,new Snapshot(UUID.randomUUID().toString(),values))==null; }
    public boolean replace(String key,String revision,Map<String,String> values) {
        var changed=new java.util.concurrent.atomic.AtomicBoolean();
        rows.computeIfPresent(key,(k,old)->{
            if(!old.revision().equals(revision)) return old;
            changed.set(true); return new Snapshot(UUID.randomUUID().toString(),values);
        }); return changed.get();
    }
}

