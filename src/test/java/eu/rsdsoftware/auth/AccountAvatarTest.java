package eu.rsdsoftware.auth;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
class AccountAvatarTest {
    @Test void initialsUseSavedNameAndHandleUnicodeAndMissingNames() {
        assertEquals("AL", AccountAvatar.initials("Alice Lee"));
        assertEquals("RS", AccountAvatar.initials("rsdstest4"));
        assertEquals("ŁŻ", AccountAvatar.initials("Łukasz Żak"));
        assertEquals("AU", AccountAvatar.initials("A"));
        assertEquals("UU", AccountAvatar.initials(null));
    }
    @Test void colourPersistsAcrossRestartAndRepeatedProviderLogin() {
        var store = new InMemoryDocumentStore();
        var first = new IdentityService(store).login("google", "issuer", "one", "Alice Lee", "alice@example.test", true);
        var next = new IdentityService(store).login("google", "issuer", "one", "Different Name", null, false);
        assertEquals("AL", first.initials());
        assertEquals(first.avatarColor(), next.avatarColor());
        assertEquals(first.initials(), next.initials());
        assertTrue(AccountAvatar.COLORS.contains(first.avatarColor()));
    }
    @Test void legacyAccountGetsOneStoredColour() {
        var store = new InMemoryDocumentStore();
        store.insert("auth:v2:account:legacy", java.util.Map.of("emailKey", "legacy-email"));
        store.insert("legacy-email", java.util.Map.of("subject", "legacy", "email", "alice@example.test", "name", "Alice Lee"));
        var first = new IdentityService(store).find("legacy").orElseThrow();
        assertEquals(first.avatarColor(), new IdentityService(store).find("legacy").orElseThrow().avatarColor());
        assertEquals(first.avatarColor(), store.get("legacy-email").orElseThrow().values().get("avatarColor"));
    }
}
