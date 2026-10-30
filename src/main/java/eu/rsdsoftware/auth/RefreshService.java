package eu.rsdsoftware.auth;
import eu.rsdsoftware.auth.store.DocumentStore;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.time.Instant;
import java.util.*;
import org.springframework.stereotype.Service;

@Service
public final class RefreshService {
    private final DocumentStore store;
    private final SecureRandom random=new SecureRandom();
    @edu.umd.cs.findbugs.annotations.SuppressFBWarnings(value="EI_EXPOSE_REP2",justification="Intentionally shared injected persistence port; atomic refresh rotation requires the same backing store. No reference is exposed.")
    public RefreshService(DocumentStore store) { this.store=store; }
    public record Rotation(String subject,String token) {}
    private String secret() { byte[] bytes=new byte[32]; random.nextBytes(bytes); return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes); }
    private static String hash(String value) {
        try { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8))); }
        catch(NoSuchAlgorithmException exception) { throw new IllegalStateException(exception); }
    }
    public String create(String subject) {
        String family=UUID.randomUUID().toString(), token=family+"."+secret();
        if(!store.insert("auth:v1:refresh:"+family,Map.of("subject",subject,"hash",hash(token),"expires",Long.toString(Instant.now().plusSeconds(604800).getEpochSecond()),"revoked","false","schema","1")))
            throw new IllegalStateException("Refresh collision");
        return token;
    }
    public Optional<Rotation> rotate(String token) {
        if(token==null || token.length()>256 || !token.contains(".")) return Optional.empty();
        String family=token.substring(0,token.indexOf('.'));
        if(!family.matches("[0-9a-f-]{36}")) return Optional.empty();
        String key="auth:v1:refresh:"+family;
        for(int attempt=0;attempt<4;attempt++) {
            var row=store.get(key); if(row.isEmpty()) return Optional.empty();
            var values=row.get().values();
            if(Boolean.parseBoolean(values.get("revoked")) || Long.parseLong(values.get("expires"))<=Instant.now().getEpochSecond()) return Optional.empty();
            boolean matches=MessageDigest.isEqual(hash(token).getBytes(StandardCharsets.US_ASCII),values.get("hash").getBytes(StandardCharsets.US_ASCII));
            var replacement=new HashMap<>(values);
            String next=family+"."+secret();
            if(!matches) replacement.put("revoked","true"); else replacement.put("hash",hash(next));
            if(store.replace(key,row.get().revision(),replacement)) return matches?Optional.of(new Rotation(values.get("subject"),next)):Optional.empty();
        }
        throw new IllegalStateException("Concurrent refresh update did not settle");
    }
    public void revoke(String token) {
        if(token==null || !token.contains(".")) return;
        String family=token.substring(0,token.indexOf('.'));
        if(!family.matches("[0-9a-f-]{36}")) return;
        String key="auth:v1:refresh:"+family;
        for(int attempt=0;attempt<4;attempt++) {
            var row=store.get(key); if(row.isEmpty()) return;
            var replacement=new HashMap<>(row.get().values()); replacement.put("revoked","true");
            if(store.replace(key,row.get().revision(),replacement)) return;
        }
        throw new IllegalStateException("Refresh revocation failed");
    }
}

