package eu.rsdsoftware.auth.store;
import java.util.Map;
import java.util.Optional;
/** Portable key/value contract. Implementations must supply atomic conditional writes and strong reads. */
public interface DocumentStore {
    record Snapshot(String revision, Map<String,String> values) {
        public Snapshot { values = Map.copyOf(values); }
    }
    Optional<Snapshot> get(String key);
    boolean insert(String key, Map<String,String> values);
    boolean replace(String key, String expectedRevision, Map<String,String> values);
}

