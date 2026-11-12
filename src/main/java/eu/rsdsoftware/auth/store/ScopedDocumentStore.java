package eu.rsdsoftware.auth.store;
import java.util.Map;
import java.util.Optional;
import java.util.Objects;
import java.util.Base64;
import java.nio.charset.StandardCharsets;

/** Service/tenant-scoped view of the shared store. */
public final class ScopedDocumentStore implements DocumentStore {
    private final DocumentStore delegate;
    private final String prefix;
    @edu.umd.cs.findbugs.annotations.SuppressFBWarnings(value="EI_EXPOSE_REP2",justification="Shared persistence port is deliberately injected; not exposed to callers.")
    public ScopedDocumentStore(DocumentStore delegate,String service,String tenant) {
        this.delegate=Objects.requireNonNull(delegate);
        prefix="scope:v1:"+component(service)+":"+component(tenant)+":";
    }
    private static String component(String value) {
        Objects.requireNonNull(value);
        if(value.isBlank() || value.length()>256 || !StandardCharsets.UTF_8.newEncoder().canEncode(value))
            throw new IllegalArgumentException("Scope and key components must be nonblank valid Unicode of at most 256 characters");
        return Base64.getUrlEncoder().withoutPadding().encodeToString(value.getBytes(StandardCharsets.UTF_8));
    }
    private String physicalKey(String key) {
        String physical=prefix+component(key);
        // Encoding and prefix are ASCII, so character count equals DynamoDB bytes.
        if(physical.length()>2048) throw new IllegalArgumentException("Encoded persistence key exceeds 2048 bytes");
        return physical;
    }
    @Override public Optional<Snapshot> get(String key) { return delegate.get(physicalKey(key)); }
    @Override public boolean insert(String key,Map<String,String> values) { return delegate.insert(physicalKey(key),values); }
    @Override public boolean replace(String key,String revision,Map<String,String> values) { return delegate.replace(physicalKey(key),revision,values); }
}
