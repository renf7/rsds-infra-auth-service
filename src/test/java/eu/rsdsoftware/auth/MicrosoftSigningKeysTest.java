package eu.rsdsoftware.auth;

import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.*;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jose.util.JSONObjectUtils;
import java.net.http.*;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class MicrosoftSigningKeysTest {
    private static final String ISSUER="https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0";
    private static JWKSelector selector() { return new JWKSelector(new JWKMatcher.Builder().keyID("key").build()); }
    private static String document() throws Exception {
        var json=new LinkedHashMap<>(new RSAKeyGenerator(2048).keyID("key").generate().toPublicJWK().toJSONObject());
        json.put("issuer",ISSUER);
        return JSONObjectUtils.toJSONString(Map.of("keys",List.of(json)));
    }
    @Test void cachesOneDocumentAndRejectsMissingKeyIssuerOrMalformedDocument() throws Exception {
        String json=document(); var calls=new AtomicInteger();
        var keys=new MicrosoftSigningKeys(()->{calls.incrementAndGet(); return json;});
        assertEquals(1,keys.select(selector(),ISSUER).size());
        assertEquals(1,keys.select(selector(),ISSUER).size());
        assertTrue(keys.select(selector(),"https://attacker.invalid").isEmpty());
        assertEquals(1,calls.get());
        assertThrows(KeySourceException.class,()->new MicrosoftSigningKeys(()->"invalid-json").select(selector(),ISSUER));
        assertThrows(KeySourceException.class,()->new MicrosoftSigningKeys(()->{throw new IllegalStateException("offline");}).select(selector(),ISSUER));
    }
    @Test void httpRetrievalUsesFixedMicrosoftEndpointAndRejectsHttpErrors() throws Exception {
        var client=mock(HttpClient.class);
        @SuppressWarnings("unchecked") HttpResponse<String> response=mock(HttpResponse.class);
        when(client.send(any(HttpRequest.class),org.mockito.ArgumentMatchers.<HttpResponse.BodyHandler<String>>any())).thenReturn(response);
        when(response.statusCode()).thenReturn(200); when(response.body()).thenReturn(document());
        assertEquals(1,new MicrosoftSigningKeys(client).select(selector(),ISSUER).size());
        verify(client).send(argThat(request->request.uri().toString().equals("https://login.microsoftonline.com/common/discovery/v2.0/keys")),org.mockito.ArgumentMatchers.<HttpResponse.BodyHandler<String>>any());
        when(response.statusCode()).thenReturn(503);
        assertThrows(KeySourceException.class,()->new MicrosoftSigningKeys(client).select(selector(),ISSUER));
        when(client.send(any(HttpRequest.class),org.mockito.ArgumentMatchers.<HttpResponse.BodyHandler<String>>any())).thenThrow(new java.io.IOException("offline"));
        assertThrows(KeySourceException.class,()->new MicrosoftSigningKeys(client).select(selector(),ISSUER));
        when(client.send(any(HttpRequest.class),org.mockito.ArgumentMatchers.<HttpResponse.BodyHandler<String>>any())).thenThrow(new InterruptedException("interrupted"));
        try { assertThrows(KeySourceException.class,()->new MicrosoftSigningKeys(client).select(selector(),ISSUER)); assertTrue(Thread.currentThread().isInterrupted()); }
        finally { Thread.interrupted(); }
    }
    @Test void refreshesExpiredKeysAndRateLimitsUnknownKeyRefresh() throws Exception {
        var now=new java.util.concurrent.atomic.AtomicReference<>(java.time.Instant.now());
        var clock=new java.time.Clock() {
            public java.time.ZoneId getZone() { return java.time.ZoneOffset.UTC; }
            public java.time.Clock withZone(java.time.ZoneId zone) { return this; }
            public java.time.Instant instant() { return now.get(); }
        };
        String json=document(); var calls=new AtomicInteger();
        var keys=new MicrosoftSigningKeys(()->{calls.incrementAndGet();return json;},clock);
        keys.select(selector(),ISSUER);
        var unknown=new JWKSelector(new JWKMatcher.Builder().keyID("rotated").build());
        keys.select(unknown,ISSUER); assertEquals(1,calls.get());
        now.set(now.get().plusSeconds(11)); keys.select(unknown,ISSUER); assertEquals(2,calls.get());
        keys.select(unknown,ISSUER); assertEquals(2,calls.get());
        now.set(now.get().plusSeconds(301)); keys.select(selector(),ISSUER); assertEquals(3,calls.get());
    }
}
