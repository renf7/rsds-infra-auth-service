package eu.rsdsoftware.auth;

import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.*;
import com.nimbusds.jose.util.JSONObjectUtils;
import java.net.URI;
import java.net.http.*;
import java.time.*;
import java.util.*;
import java.util.function.Supplier;

/** Retains Microsoft's nonstandard JWK issuer attribute, which Nimbus JWK parsing discards. */
final class MicrosoftSigningKeys {
    private static final URI ENDPOINT=URI.create("https://login.microsoftonline.com/common/discovery/v2.0/keys");
    private final Supplier<String> retrieve;
    private final Clock clock;
    private List<Map<String,Object>> cached=List.of();
    private Instant loaded=Instant.EPOCH;

    MicrosoftSigningKeys() {
        this(HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).followRedirects(HttpClient.Redirect.NEVER).build());
    }
    MicrosoftSigningKeys(HttpClient client) {
        clock=Clock.systemUTC();
        retrieve=() -> {
            try {
                var response=client.send(HttpRequest.newBuilder(ENDPOINT).timeout(Duration.ofSeconds(10)).GET().build(),HttpResponse.BodyHandlers.ofString());
                if(response.statusCode()!=200 || response.body().length()>1_048_576)
                    throw new IllegalStateException("Microsoft signing keys unavailable");
                return response.body();
            } catch(InterruptedException failure) {
                Thread.currentThread().interrupt(); throw new IllegalStateException("Microsoft signing keys interrupted",failure);
            } catch(java.io.IOException failure) {
                throw new IllegalStateException("Microsoft signing keys unavailable",failure);
            }
        };
    }
    MicrosoftSigningKeys(Supplier<String> retrieve) { this(retrieve,Clock.systemUTC()); }
    MicrosoftSigningKeys(Supplier<String> retrieve,Clock clock) { this.retrieve=retrieve; this.clock=clock; }

    synchronized List<JWK> select(JWKSelector selector,String issuer) throws KeySourceException {
        Instant now=clock.instant();
        if(loaded.plusSeconds(300).isBefore(now)) reload(now);
        var result=matching(selector,issuer);
        // Allow signing-key rotation while bounding refreshes for attacker-chosen key IDs.
        if(result.isEmpty() && loaded.plusSeconds(10).isBefore(now)) {
            reload(now); result=matching(selector,issuer);
        }
        return result;
    }
    private void reload(Instant now) throws KeySourceException {
        try {
            var document=JSONObjectUtils.parse(retrieve.get());
            cached=List.copyOf(Arrays.asList(JSONObjectUtils.getJSONObjectArray(document,"keys")));
            loaded=now;
        } catch(java.text.ParseException | IllegalStateException failure) {
            throw new KeySourceException("Cannot load Microsoft signing keys",failure);
        }
    }
    private List<JWK> matching(JWKSelector selector,String issuer) throws KeySourceException {
        var allowed=new ArrayList<JWK>();
        try {
            for(var entry:cached) {
                Object keyIssuer=entry.get("issuer");
                if(issuer.equals(keyIssuer) || (MicrosoftOidcDecoderFactory.AUTHORITY+"{tenantid}/v2.0").equals(keyIssuer))
                    allowed.add(JWK.parse(entry));
            }
            return selector.select(new JWKSet(allowed));
        } catch(java.text.ParseException failure) {
            throw new KeySourceException("Invalid Microsoft signing key",failure);
        }
    }
}
