package eu.rsdsoftware.auth;

import java.time.Instant;
import java.util.Map;

/** Explicit transient namespaces only; permanent identity/binding records are excluded. */
public final class TransientRetention {
    private TransientRetention() {}
    public static Instant deadline(String key,Map<String,String> values,long retentionSeconds) {
        if(retentionSeconds<86400 || retentionSeconds>2592000) throw new IllegalArgumentException("Retention must be 1 to 30 days");
        String field;
        if(key.startsWith("auth:v1:refresh:") || key.startsWith("auth:v2:pending:")) field="expires";
        else if(key.startsWith("auth:v2:mail-window:")) field="until";
        else if(key.startsWith("auth:v2:mail-rate:")) field="after";
        else throw new IllegalArgumentException("Permanent or unknown namespace cannot expire");
        long seconds=Long.parseLong(values.get(field));
        if(seconds<=0) throw new IllegalArgumentException("Invalid expiry");
        return Instant.ofEpochSecond(seconds).plusSeconds(retentionSeconds);
    }
}
