package eu.rsdsoftware.auth;
import java.util.*;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
class EmailVerificationTest {
    private final InMemoryDocumentStore store=new InMemoryDocumentStore();
    private final AtomicReference<String> delivered=new AtomicReference<>();
    private final EmailVerification service=new EmailVerification(store,(address,code)->delivered.set(code));
    private ProviderProfile profile(String email) {return new ProviderProfile("microsoft","issuer","stable-sub","Alice",email,false);}
    @Test void onlyDeliveredCodeCanVerifyTheProviderBoundEmailAndItIsSingleUse() {
        String flow=service.begin(profile("alice@example.test"));
        assertFalse(service.status(flow).needsEmail()); assertNotNull(delivered.get());
        assertThrows(IllegalArgumentException.class,()->service.verify(flow,"wrong"));
        var verified=service.verify(flow,delivered.get());
        assertEquals("alice@example.test",verified.email()); assertTrue(verified.verified());
        assertEquals("stable-sub",verified.externalSubject());
        assertThrows(IllegalArgumentException.class,()->service.verify(flow,delivered.get()));
    }
    @Test void missingEmailRequiresExplicitEntryAndCannotChangeAfterSending() {
        String flow=service.begin(profile(null)); assertTrue(service.status(flow).needsEmail());
        service.send(flow," Alice@Example.test "); assertFalse(service.status(flow).needsEmail());
        assertThrows(IllegalArgumentException.class,()->service.send(flow,"victim@example.test"));
        assertEquals("alice@example.test",service.verify(flow,delivered.get()).email());
    }
    @Test void attemptsExpiryInvalidFlowsAndDeliveryErrorsFailClosed() {
        String flow=service.begin(profile("attempts@example.test"));
        String correct=delivered.get(); for(int i=0;i<5;i++) assertThrows(IllegalArgumentException.class,()->service.verify(flow,"0000000"));
        assertThrows(IllegalArgumentException.class,()->service.verify(flow,correct));
        assertThrows(IllegalArgumentException.class,()->service.status(null));
        String expired=service.begin(profile("expired@example.test"));
        String key="auth:v2:pending:"+EmailAddress.hash(expired); var row=store.get(key).orElseThrow();
        var values=new HashMap<>(row.values()); values.put("expires","1"); store.replace(key,row.revision(),values);
        assertThrows(IllegalArgumentException.class,()->service.verify(expired,delivered.get()));
        var failing=new EmailVerification(store,(email,code)->{throw new IllegalStateException("SMTP unavailable");});
        assertThrows(IllegalStateException.class,()->failing.begin(profile("failed@example.test")));
    }
    @Test void throttlingPreventsRepeatedEmailsAndNoPlaintextCodeIsStored() {
        String flow=service.begin(profile("rate@example.test"));
        var values=store.get("auth:v2:pending:"+EmailAddress.hash(flow)).orElseThrow().values();
        assertFalse(values.containsValue(delivered.get())); assertFalse(values.containsValue(flow));
        assertThrows(IllegalArgumentException.class,()->service.begin(profile("rate@example.test")));
    }
}
