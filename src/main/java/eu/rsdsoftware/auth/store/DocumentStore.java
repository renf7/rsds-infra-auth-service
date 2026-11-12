package eu.rsdsoftware.auth.store;
import java.util.Map;
import java.util.Optional;
/** Portable key/value contract. Implementations must supply atomic conditional writes and strong reads. */
public interface DocumentStore {
    record Snapshot(String revision, Map<String,String> values, java.time.Instant deleteAfter) {
        public Snapshot(String revision, Map<String,String> values) { this(revision,values,null); }
        public Snapshot { values = Map.copyOf(values); }
    }
    Optional<Snapshot> get(String key);
    boolean insert(String key, Map<String,String> values);
    boolean replace(String key, String expectedRevision, Map<String,String> values);
    /** Physical deletion may be asynchronous; expiry never substitutes for authorization checks. */
    default boolean insertExpiring(String key, Map<String,String> values, java.time.Instant deleteAfter) {
        throw new UnsupportedOperationException("Adapter must implement retention metadata");
    }
    default boolean replaceExpiring(String key, String revision, Map<String,String> values, java.time.Instant deleteAfter) {
        throw new UnsupportedOperationException("Adapter must implement retention metadata");
    }
}

