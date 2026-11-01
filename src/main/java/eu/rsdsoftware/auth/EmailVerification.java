package eu.rsdsoftware.auth;
import eu.rsdsoftware.auth.store.DocumentStore;
import java.security.*;
import java.time.Instant;
import java.util.*;
import org.springframework.stereotype.Service;

@Service
public final class EmailVerification {
    private final DocumentStore store;
    private final VerificationMail mail;
    private final SecureRandom random=new SecureRandom();
    public record Status(boolean needsEmail,String maskedEmail) {}
    @edu.umd.cs.findbugs.annotations.SuppressFBWarnings(value="EI_EXPOSE_REP2",justification="Injected atomic persistence and SMTP ports are deliberately shared; no mutable reference is exposed.")
    public EmailVerification(DocumentStore store,VerificationMail mail) {this.store=store; this.mail=mail;}
    private String secret() {byte[] bytes=new byte[32]; random.nextBytes(bytes); return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);}
    private static long now() {return Instant.now().getEpochSecond();}
    private DocumentStore.Snapshot pending(String flow) {
        if(flow==null || !flow.matches("[A-Za-z0-9_-]{43}")) throw new IllegalArgumentException("Sign in again");
        var row=store.get("auth:v2:pending:"+EmailAddress.hash(flow)).orElseThrow(()->new IllegalArgumentException("Sign in again"));
        if(Long.parseLong(row.values().get("expires"))<=now() || Boolean.parseBoolean(row.values().get("used")))
            throw new IllegalArgumentException("Sign in again");
        return row;
    }
    public String begin(ProviderProfile profile) {
        String flow=secret(); var values=new HashMap<String,String>();
        values.put("provider",profile.provider()); values.put("issuer",profile.issuer()); values.put("external",profile.externalSubject());
        values.put("name",profile.name()); values.put("expires",Long.toString(now()+600)); values.put("used","false"); values.put("attempts","0");
        if(!store.insert("auth:v2:pending:"+EmailAddress.hash(flow),values)) throw new IllegalStateException("Challenge collision");
        if(profile.email()!=null && !profile.email().isBlank()) send(flow,profile.email());
        return flow;
    }
    public Status status(String flow) {
        String email=pending(flow).values().get("email");
        return new Status(email==null,email==null?"":email.substring(0,1)+"***"+email.substring(email.indexOf('@')));
    }
    private void throttle(String email,String provider) {
        String globalKey="auth:v2:mail-window:"+EmailAddress.hash(email);
        boolean acquired=false;
        for(int attempt=0;attempt<4 && !acquired;attempt++) {
            var row=store.get(globalKey); var next=new HashMap<String,String>();
            boolean active=row.isPresent() && Long.parseLong(row.get().values().get("until"))>now();
            int count=active?Integer.parseInt(row.get().values().get("count")):0;
            if(count>=5) throw new IllegalArgumentException("Wait before requesting another email");
            next.put("count",Integer.toString(count+1)); next.put("until",active?row.orElseThrow().values().get("until"):Long.toString(now()+900));
            acquired=row.isEmpty()?store.insert(globalKey,next):store.replace(globalKey,row.get().revision(),next);
        }
        if(!acquired) throw new IllegalArgumentException("Wait before requesting another email");
        String key="auth:v2:mail-rate:"+EmailAddress.hash(provider+":"+email); var next=Map.of("after",Long.toString(now()+60));
        for(int attempt=0;attempt<4;attempt++) {
            var row=store.get(key);
            if(row.isEmpty()) {if(store.insert(key,next)) return;}
            else {
                if(Long.parseLong(row.get().values().get("after"))>now()) throw new IllegalArgumentException("Wait before requesting another email");
                if(store.replace(key,row.get().revision(),next)) return;
            }
        }
        throw new IllegalArgumentException("Wait before requesting another email");
    }
    public void send(String flow,String address) {
        var row=pending(flow); if(row.values().containsKey("email")) throw new IllegalArgumentException("Code already sent");
        String email=EmailAddress.normalize(address); throttle(email,row.values().get("provider"));
        String code=String.format(Locale.ROOT,"%06d",random.nextInt(1_000_000));
        var values=new HashMap<>(row.values()); values.put("email",email); values.put("codeHash",EmailAddress.hash(flow+":"+code));
        if(!store.replace("auth:v2:pending:"+EmailAddress.hash(flow),row.revision(),values)) throw new IllegalArgumentException("Sign in again");
        mail.send(email,code);
    }
    public ProviderProfile verify(String flow,String code) {
        for(int attempt=0;attempt<4;attempt++) {
            var row=pending(flow); var values=new HashMap<>(row.values()); int failures=Integer.parseInt(values.get("attempts"));
            boolean matches=code!=null && code.matches("[0-9]{6}") && values.containsKey("codeHash")
                && MessageDigest.isEqual(EmailAddress.hash(flow+":"+code).getBytes(java.nio.charset.StandardCharsets.US_ASCII),
                    values.get("codeHash").getBytes(java.nio.charset.StandardCharsets.US_ASCII));
            values.put("attempts",Integer.toString(failures+1)); values.put("used",Boolean.toString(matches || failures>=4));
            if(!store.replace("auth:v2:pending:"+EmailAddress.hash(flow),row.revision(),values)) continue;
            if(!matches) throw new IllegalArgumentException("Invalid or expired code");
            return new ProviderProfile(values.get("provider"),values.get("issuer"),values.get("external"),values.get("name"),values.get("email"),true);
        }
        throw new IllegalArgumentException("Sign in again");
    }
}
