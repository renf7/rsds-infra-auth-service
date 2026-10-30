package eu.rsdsoftware.auth;
import eu.rsdsoftware.auth.store.DocumentStore;
import java.nio.charset.StandardCharsets;
import java.util.*;
import org.springframework.stereotype.Service;

@Service
public final class IdentityService {
    private final DocumentStore store;
    public record Identity(String subject,String provider,String name,List<String> roles) {
        public Identity { roles = List.copyOf(roles); }
    }
    @edu.umd.cs.findbugs.annotations.SuppressFBWarnings(value="EI_EXPOSE_REP2",justification="Intentionally shared injected persistence port; defensive copying would break atomic database semantics. No reference is exposed.")
    public IdentityService(DocumentStore store) { this.store=store; }
    public Identity login(String provider,String issuer,String externalSubject,String displayName) {
        if (externalSubject == null || externalSubject.isBlank()) throw new IllegalArgumentException("Missing immutable provider subject");
        String subject=UUID.nameUUIDFromBytes((provider+"\n"+issuer+"\n"+externalSubject).getBytes(StandardCharsets.UTF_8)).toString();
        String key="auth:v1:identity:"+subject;
        // Provider email/name/claims never create roles or link separate provider identities.
        store.insert(key,Map.of("subject",subject,"provider",provider,"name",displayName,"roles","","schema","1"));
        return find(subject).orElseThrow();
    }
    public Optional<Identity> find(String subject) {
        return store.get("auth:v1:identity:"+subject).map(row -> {
            var v=row.values();
            var roles=Arrays.stream(v.getOrDefault("roles","").split(",")).filter(r -> Set.of("JOB_REPLY","COMPETENCE_BUILDER").contains(r)).toList();
            return new Identity(v.get("subject"),v.get("provider"),v.get("name"),roles);
        });
    }
}

