package eu.rsdsoftware.auth;

import static org.junit.jupiter.api.Assertions.*;
import java.util.List;
import org.junit.jupiter.api.Test;

class AccountIdentityContractTest {
    @Test void identicalNamesAndSubjectsRemainScopedToProviderAndIssuer() {
        var service=new IdentityService(new InMemoryDocumentStore());
        var google=service.login("google","issuer","same","Alice",null,false);
        var github=service.login("github","issuer","same","Alice",null,false);
        var otherTenant=service.login("google","other-issuer","same","Alice",null,false);
        assertNotEquals(google.subject(),github.subject());
        assertNotEquals(google.subject(),otherTenant.subject());
        assertEquals(google,service.login("google","issuer","same","Renamed","changed@example.test",true));
    }

    @Test void duplicateChangedAndClearedContactEmailsNeverChangeIdentityOrRoles() {
        var service=new IdentityService(new InMemoryDocumentStore());
        var first=service.login("google","issuer","first","Alice",null,false);
        var second=service.login("google","issuer","second","Alice",null,false);
        for(String email:List.of("same@example.test","changed@example.test","")) {
            service.saveContactEmail(first.subject(),email);
            service.saveContactEmail(second.subject(),email);
            assertEquals(email,service.settings(first.subject()).email());
            assertEquals(email,service.settings(second.subject()).email());
            assertEquals(first,service.linked("google","issuer","first").orElseThrow());
            assertEquals(second,service.linked("google","issuer","second").orElseThrow());
            assertTrue(service.find(first.subject()).orElseThrow().roles().isEmpty());
            assertTrue(service.find(second.subject()).orElseThrow().roles().isEmpty());
        }
    }

    @Test void controlCharactersCannotProduceAmbiguousIdentityKeys() {
        var service=new IdentityService(new InMemoryDocumentStore());
        for(String invalid:List.of("issuer\nsubject","issuer\rsubject","issuer\u0000subject","issuer\tsubject")) {
            assertThrows(IllegalArgumentException.class,()->service.login("google",invalid,"subject","Alice",null,false));
            assertThrows(IllegalArgumentException.class,()->service.login("google","issuer",invalid,"Alice",null,false));
            assertThrows(IllegalArgumentException.class,()->service.linked("google",invalid,"subject"));
        }
        assertDoesNotThrow(()->service.login("google","issuer","legitimate-subject","Alice",null,false));
    }
}
