package eu.rsdsoftware.auth;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
class OptionalEmailAccountTest {
    @Test void missingEmailCreatesStableProviderAccountWithoutReservingAnEmail() {
        var service=new IdentityService(new InMemoryDocumentStore());
        var first=service.login("facebook","facebook","no-email","Alice",null,false);
        assertEquals("",first.email());
        assertEquals(first,service.login("facebook","facebook","no-email","Changed",null,false));
        var other=service.login("facebook","facebook","other","Alice",null,false);
        assertNotEquals(first.subject(),other.subject());
    }
    @Test void optionalEmailIsSavedWithoutLinkingOrGrantingVerifiedOwnership() {
        var service=new IdentityService(new InMemoryDocumentStore());
        var owner=service.login("google","google","owner","Owner","owner@example.test",true);
        var account=service.login("facebook","facebook","no-email","Alice",null,false);
        service.saveContactEmail(account.subject()," Owner@Example.test ");
        assertEquals("owner@example.test",service.settings(account.subject()).email());
        assertFalse(service.settings(account.subject()).emailVerified());
        assertEquals("",service.find(account.subject()).orElseThrow().email());
        assertNotEquals(owner.subject(),account.subject());
        assertEquals(account.subject(),service.login("facebook","facebook","no-email","Alice","owner@example.test",true).subject());
        service.saveContactEmail(account.subject(),"");
        assertEquals("",service.settings(account.subject()).email());
        assertThrows(IllegalArgumentException.class,()->service.saveContactEmail(account.subject(),"invalid"));
    }
}
