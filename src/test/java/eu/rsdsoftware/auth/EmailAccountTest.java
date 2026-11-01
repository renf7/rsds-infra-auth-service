package eu.rsdsoftware.auth;
import java.util.*;
import java.util.concurrent.*;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
class EmailAccountTest {
    @Test void verifiedProvidersAutomaticallyShareOneNormalizedEmailAccount() {
        var service=new IdentityService(new InMemoryDocumentStore());
        var first=service.login("google","google-issuer","google-sub","Alice"," Alice@Example.test ",true);
        for(String provider:ProviderRegistrations.PROVIDERS) {
            var next=service.login(provider,provider+"-issuer",provider+"-sub","New name","alice@example.test",true);
            assertEquals(first.subject(),next.subject()); assertEquals("alice@example.test",next.email());
            assertTrue(next.roles().isEmpty());
        }
        assertEquals(first,service.find(first.subject()).orElseThrow());
    }
    @Test void unverifiedMissingAndMalformedEmailsCannotReserveOrLinkAccounts() {
        var service=new IdentityService(new InMemoryDocumentStore());
        assertThrows(IllegalArgumentException.class,()->service.login("microsoft","issuer","attacker","Alice","alice@example.test",false));
        for(String email:List.of("","invalid","a@b\nBcc: victim@example.test"))
            assertThrows(IllegalArgumentException.class,()->service.login("github","issuer","sub","Alice",email,true));
        var owner=service.login("google","issuer","owner","Alice","alice@example.test",true);
        assertNotNull(owner.subject());
    }
    @Test void establishedProviderBindingCannotMoveToAnotherAccountWhenEmailChanges() {
        var service=new IdentityService(new InMemoryDocumentStore());
        var alice=service.login("apple","issuer","stable-sub","Alice","relay@privaterelay.appleid.com",true);
        var bob=service.login("google","issuer","bob","Bob","bob@example.test",true);
        assertEquals(alice,service.login("apple","issuer","stable-sub","Changed","bob@example.test",false));
        assertEquals(alice,service.login("apple","issuer","stable-sub","Changed",null,false));
        assertNotEquals(alice.subject(),bob.subject());
    }
    @Test void simultaneousFirstLoginsUseAtomicEmailUniqueness() throws Exception {
        var service=new IdentityService(new InMemoryDocumentStore());
        try(var pool=Executors.newVirtualThreadPerTaskExecutor()) {
            var tasks=new ArrayList<Callable<String>>();
            for(int i=0;i<20;i++) { final int id=i;
                tasks.add(()->service.login("google","issuer","sub-"+id,"Alice","race@example.test",true).subject());
            }
            var ids=new HashSet<String>(); for(var result:pool.invokeAll(tasks)) ids.add(result.get());
            assertEquals(1,ids.size());
        }
    }
}
