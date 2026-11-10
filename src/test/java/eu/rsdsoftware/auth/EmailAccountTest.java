package eu.rsdsoftware.auth;
import java.util.*;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
class EmailAccountTest {
    @Test void matchingContactAddressesNeverLinkProviderAccounts() {
        var service=new IdentityService(new InMemoryDocumentStore());
        var first=service.login("google","issuer","one","Alice","alice@example.test",true);
        var second=service.login("github","github","two","Alice","alice@example.test",true);
        service.saveContactEmail(first.subject()," Alice@Example.test ");
        service.saveContactEmail(second.subject(),"alice@example.test");
        assertNotEquals(first.subject(),second.subject());
        assertEquals("alice@example.test",service.settings(first.subject()).email());
        assertFalse(service.settings(first.subject()).emailVerified());
        assertFalse(service.settings(second.subject()).emailVerified());
    }
    @Test void providerEmailIsNeverCopiedToOptionalContactData() {
        var service=new IdentityService(new InMemoryDocumentStore());
        var account=service.login("microsoft","issuer","sub","Alice","alice@example.test",false);
        assertEquals("",account.email());
        assertEquals("",service.settings(account.subject()).email());
        for(String email:List.of("invalid","a@b\nBcc: victim@example.test"))
            assertThrows(IllegalArgumentException.class,()->service.saveContactEmail(account.subject(),email));
    }
    @Test void legacyBindingsKeepTheirAccountRolesAndAvatarWithoutNewEmailLinking() {
        var store=new InMemoryDocumentStore();
        var accountKey="auth:v2:email:"+EmailAddress.hash("alice@example.test");
        store.insert(accountKey,Map.of("subject","legacy","email","alice@example.test","name","Alice","roles","JOB_REPLY","avatarColor",AccountAvatar.COLORS.getFirst()));
        store.insert("auth:v2:account:legacy",Map.of("emailKey",accountKey));
        for(String provider:List.of("google","github")) {
            String binding="auth:v2:binding:"+EmailAddress.hash(provider+"\nissuer\nstable");
            store.insert(binding,Map.of("subject","legacy"));
        }
        var service=new IdentityService(store);
        var legacy=service.login("google","issuer","stable","Changed",null,false);
        assertEquals("legacy",legacy.subject());
        assertEquals(List.of("JOB_REPLY"),legacy.roles());
        assertEquals(legacy,service.login("github","issuer","stable","Alice","other@example.test",true));
        assertEquals(AccountAvatar.COLORS.getFirst(),legacy.avatarColor());
        var fresh=service.login("apple","issuer","fresh","Alice","alice@example.test",true);
        assertNotEquals(legacy.subject(),fresh.subject());
        assertTrue(fresh.roles().isEmpty());
    }
}
