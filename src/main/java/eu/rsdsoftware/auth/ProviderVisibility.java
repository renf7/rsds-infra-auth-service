package eu.rsdsoftware.auth;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;
import org.springframework.core.env.Environment;

/** Presentation policy only: never changes OAuth registration or existing sessions. */
final class ProviderVisibility {
    private static final Set<String> SUPPORTED=Set.of("facebook","microsoft","google","github");
    private final Path file;

    ProviderVisibility(Environment env) {
        String configured=env.getProperty("rsds.auth.provider-visibility-file","");
        file=configured.isBlank()?null:Path.of(configured);
    }

    Set<String> visible() {
        if(file==null) return SUPPORTED;
        // Open on every request so Kubernetes' atomic symlink replacement is observed.
        try(var input=Files.newInputStream(file)) {
            byte[] bytes=input.readNBytes(1025);
            if(bytes.length>1024) return Set.of();
            String value=new String(bytes,StandardCharsets.UTF_8).strip();
            if(value.isEmpty()) return Set.of();
            Set<String> selected=Arrays.stream(value.split(",",-1)).map(String::strip).collect(Collectors.toUnmodifiableSet());
            return SUPPORTED.containsAll(selected)?selected:Set.of();
        } catch(IOException exception) {
            return Set.of();
        }
    }
}
