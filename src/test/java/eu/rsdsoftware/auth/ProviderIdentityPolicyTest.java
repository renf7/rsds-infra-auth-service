package eu.rsdsoftware.auth;

import java.util.*;
import java.util.concurrent.*;
import org.junit.jupiter.api.Test;
import org.springframework.mock.env.MockEnvironment;
import static org.junit.jupiter.api.Assertions.*;

class ProviderIdentityPolicyTest {
    @Test void matchingVerifiedEmailNeverLinksNewProviderIdentities() {
        var service=new IdentityService(new InMemoryDocumentStore());
        var subjects=new HashSet<String>();
        for(String provider:ProviderRegistrations.PROVIDERS) {
            var identity=service.login(provider,"issuer-"+provider,"same-sub","Alice","alice@example.test",true);
            assertEquals("",identity.email());
            assertEquals("",service.settings(identity.subject()).email());
            assertTrue(identity.roles().isEmpty());
            subjects.add(identity.subject());
        }
        assertEquals(5,subjects.size());
    }
    @Test void sameBindingConvergesButDistinctSubjectsAndIssuersRemainSeparate() throws Exception {
        var service=new IdentityService(new InMemoryDocumentStore());
        try(var pool=Executors.newVirtualThreadPerTaskExecutor()) {
            var tasks=new ArrayList<Callable<String>>();
            for(int i=0;i<20;i++) tasks.add(()->service.login("google","issuer","stable","Alice",null,false).subject());
            var subjects=new HashSet<String>();
            for(var result:pool.invokeAll(tasks)) subjects.add(result.get());
            assertEquals(1,subjects.size());
            var first=service.find(subjects.iterator().next()).orElseThrow();
            assertEquals(first,service.login("google","issuer","stable","Changed","invalid provider email",true));
            assertNotEquals(first.subject(),service.login("google","other-issuer","stable","Alice",null,false).subject());
            assertNotEquals(first.subject(),service.login("google","issuer","different","Alice",null,false).subject());
        }
    }
    @Test void everyProviderRequestsProfileWithoutEmailScopesOrFields() {
        var providers=new ProviderRegistrations(TestSigningMaterial.settings(true),new MockEnvironment());
        for(var registration:providers) {
            assertFalse(registration.getScopes().contains("email"));
            assertFalse(registration.getScopes().contains("user:email"));
        }
    }
    @Test void internalJwtContainsOnlyInternalIdentityAndAuthorizationClaims() throws Exception {
        var identity=new IdentityService(new InMemoryDocumentStore()).login("google","issuer","sub","Alice",null,false);
        var tokens=new TokenService(TestSigningMaterial.settings(true));
        var jwt=tokens.decoder().decode(tokens.issue(identity));
        assertEquals(identity.subject(),jwt.getSubject());
        assertFalse(jwt.getClaims().containsKey("email"));
        assertFalse(jwt.getClaims().containsKey("name"));
        assertFalse(jwt.getClaims().containsKey("provider"));
        assertNotNull(jwt.getHeaders().get("kid"));
    }
    @Test void retryRepairsAnInterruptedIndexWriteWithoutReplacingTheAccount() {
        var rows=new InMemoryDocumentStore();
        var interrupted=new java.util.concurrent.atomic.AtomicBoolean();
        eu.rsdsoftware.auth.store.DocumentStore crash=new eu.rsdsoftware.auth.store.DocumentStore() {
            public Optional<Snapshot> get(String key) {return rows.get(key);}
            public boolean insert(String key,Map<String,String> value) {
                if(key.startsWith("auth:v2:account:") && interrupted.compareAndSet(false,true))
                    throw new IllegalStateException("Simulated interrupted write");
                return rows.insert(key,value);
            }
            public boolean replace(String key,String revision,Map<String,String> value) {return rows.replace(key,revision,value);}
        };
        assertThrows(IllegalStateException.class,()->new IdentityService(crash).login("github","github","sub","Alice",null,false));
        String binding="auth:v2:binding:"+EmailAddress.hash("github\ngithub\nsub");
        String key="auth:v2:provider-account:"+EmailAddress.hash(binding);
        var before=rows.get(key).orElseThrow().values();
        var recovered=new IdentityService(rows).login("github","github","sub","Changed","any@example.test",true);
        assertEquals(before.get("subject"),recovered.subject());
        assertEquals(before.get("avatarColor"),recovered.avatarColor());
        assertTrue(recovered.roles().isEmpty());
    }
}
