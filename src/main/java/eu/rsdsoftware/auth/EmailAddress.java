package eu.rsdsoftware.auth;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.*;
/** Application uniqueness policy: trim/lowercase, without rewriting aliases or relay addresses. */
public final class EmailAddress {
    private EmailAddress() {}
    public static String normalize(String value) {
        if(value==null) throw new IllegalArgumentException("Email verification required");
        String email=value.strip().toLowerCase(Locale.ROOT);
        String[] parts=email.split("@",-1);
        if(email.length()>254 || parts.length!=2 || parts[0].isEmpty() || parts[0].length()>64
                || !parts[0].matches("[a-z0-9!#$%&'*+/=?^_`{|}~.-]+")
                || email.contains("..") || email.startsWith(".") || email.contains(".@"))
            throw new IllegalArgumentException("A valid email is required");
        String[] labels=parts[1].split("\\.",-1);
        if(labels.length<2) throw new IllegalArgumentException("A valid email is required");
        for(String label:labels) if(label.isEmpty() || label.length()>63 || !label.matches("[a-z0-9-]+") || label.startsWith("-") || label.endsWith("-"))
            throw new IllegalArgumentException("A valid email is required");
        return email;
    }
    public static String hash(String value) {
        try {return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8)));}
        catch(NoSuchAlgorithmException exception) {throw new IllegalStateException(exception);}
    }
}
