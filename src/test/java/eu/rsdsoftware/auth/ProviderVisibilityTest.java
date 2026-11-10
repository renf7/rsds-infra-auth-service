package eu.rsdsoftware.auth;

import static org.junit.jupiter.api.Assertions.*;
import java.nio.file.*;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.mock.env.MockEnvironment;

class ProviderVisibilityTest {
    @TempDir Path directory;

    @Test void defaultsExcludeDeferredApple() {
        assertEquals(Set.of("facebook","microsoft","google","github"),new ProviderVisibility(new MockEnvironment()).visible());
    }

    @Test void reloadsReplacementAndFailsClosedWithoutRestart() throws Exception {
        Path file=directory.resolve("visible-providers");
        var policy=new ProviderVisibility(new MockEnvironment().withProperty("rsds.auth.provider-visibility-file",file.toString()));
        assertTrue(policy.visible().isEmpty());
        Files.writeString(file,"GitHub, GOOGLE\n");
        assertEquals(Set.of("github","google"),policy.visible());
        Path replacement=directory.resolve("replacement");
        Files.writeString(replacement,"microsoft");
        Files.move(replacement,file,StandardCopyOption.REPLACE_EXISTING);
        assertEquals(Set.of("microsoft"),policy.visible());
        for(String invalid:new String[]{"", "github,unknown", "apple", "github,", "x".repeat(1025)}) {
            Files.writeString(file,invalid);
            assertTrue(policy.visible().isEmpty());
        }
        Files.delete(file);
        assertTrue(policy.visible().isEmpty());
    }
}
