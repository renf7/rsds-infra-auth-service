package eu.rsdsoftware.auth;
import eu.rsdsoftware.auth.store.DocumentStore;
import java.util.*;
import org.springframework.stereotype.Service;
@Service
public final class IdentityService {
    private final DocumentStore store;
    public record Identity(String subject,String email,String name,List<String> roles,String initials,String avatarColor) {
        public Identity(String subject,String email,String name,List<String> roles) {
            this(subject,email,name,roles,AccountAvatar.initials(name),AccountAvatar.COLORS.getFirst());
        }
        public Identity {roles=List.copyOf(roles);}
    }
    @edu.umd.cs.findbugs.annotations.SuppressFBWarnings(value="EI_EXPOSE_REP2",justification="Intentionally shared injected persistence port; atomic account uniqueness requires the same backing store. No reference is exposed.")
    public IdentityService(DocumentStore store) {this.store=store;}
    private static String bindingKey(String provider,String issuer,String externalSubject) {
        if(!ProviderRegistrations.PROVIDERS.contains(provider) || issuer==null || externalSubject==null || externalSubject.isBlank())
            throw new IllegalArgumentException("Missing immutable provider identity");
        return "auth:v2:binding:"+EmailAddress.hash(provider+"\n"+issuer+"\n"+externalSubject);
    }
    public Optional<Identity> linked(String provider,String issuer,String externalSubject) {
        return store.get(bindingKey(provider,issuer,externalSubject)).flatMap(row->find(row.values().get("subject")));
    }
    public Identity login(String provider,String issuer,String externalSubject,String name,String email,boolean verified) {
        String binding=bindingKey(provider,issuer,externalSubject);
        var existing=linked(provider,issuer,externalSubject); if(existing.isPresent()) return existing.get();
        if(!verified && (email==null || email.isBlank())) {
            String key="auth:v2:provider-account:"+EmailAddress.hash(binding);
            store.insert(key,Map.of("subject",UUID.randomUUID().toString(),"email","",
                "name",name==null?"User":name.substring(0,Math.min(name.length(),128)),"roles","","schema","2","avatarColor",AccountAvatar.randomColor()));
            var account=store.get(key).orElseThrow().values();
            store.insert("auth:v2:account:"+account.get("subject"),Map.of("emailKey",key));
            store.insert(binding,Map.of("subject",account.get("subject")));
            return linked(provider,issuer,externalSubject).orElseThrow();
        }
        if(!verified) throw new IllegalArgumentException("Email verification required");
        String normalized=EmailAddress.normalize(email), emailKey="auth:v2:email:"+EmailAddress.hash(normalized);
        store.insert(emailKey,Map.of("subject",UUID.randomUUID().toString(),"email",normalized,
            "name",name==null?"User":name.substring(0,Math.min(name.length(),128)),"roles","","schema","2","avatarColor",AccountAvatar.randomColor()));
        var account=store.get(emailKey).orElseThrow().values();
        store.insert("auth:v2:account:"+account.get("subject"),Map.of("emailKey",emailKey));
        // Crash retries repair indices. Existing provider bindings are never reassigned.
        store.insert(binding,Map.of("subject",account.get("subject")));
        return linked(provider,issuer,externalSubject).orElseThrow();
    }
    public Optional<Identity> find(String subject) {
        if(subject==null) return Optional.empty();
        return store.get("auth:v2:account:"+subject).map(index->{
            String key=index.values().get("emailKey");
            var v=accountWithAvatar(key);
            var roles=Arrays.stream(v.getOrDefault("roles","").split(",")).filter(Set.of("JOB_REPLY","COMPETENCE_BUILDER")::contains).toList();
            return new Identity(v.get("subject"),v.get("email"),v.get("name"),roles,AccountAvatar.initials(v.get("name")),v.get("avatarColor"));
        });
    }
    public record Settings(String email,boolean emailVerified) {}
    public Settings settings(String subject) {
        var index=store.get("auth:v2:account:"+subject).orElseThrow(()->new IllegalArgumentException("Unknown account"));
        var row=store.get(index.values().get("emailKey")).orElseThrow().values();
        String verified=row.getOrDefault("email","");
        String contact=row.getOrDefault("contactEmail",verified);
        return new Settings(contact,!verified.isEmpty() && verified.equals(contact));
    }
    public void saveContactEmail(String subject,String email) {
        String normalized=email==null || email.isBlank()?"":EmailAddress.normalize(email);
        String key=store.get("auth:v2:account:"+subject).orElseThrow(()->new IllegalArgumentException("Unknown account")).values().get("emailKey");
        for(int attempt=0;attempt<20;attempt++) {
            var row=store.get(key).orElseThrow();
            var updated=new HashMap<>(row.values()); updated.put("contactEmail",normalized);
            // Contact data is never an identity index or proof of email ownership.
            if(store.replace(key,row.revision(),updated)) return;
        }
        throw new IllegalStateException("Concurrent settings update did not settle");
    }
    private Map<String,String> accountWithAvatar(String key) {
        for(int attempt=0;attempt<20;attempt++) {
            var row=store.get(key).orElseThrow();
            if(AccountAvatar.COLORS.contains(row.values().getOrDefault("avatarColor",""))) return row.values();
            var updated=new HashMap<>(row.values()); updated.put("avatarColor",AccountAvatar.randomColor());
            if(store.replace(key,row.revision(),updated)) return updated;
        }
        throw new IllegalStateException("Concurrent avatar update did not settle");
    }
}
