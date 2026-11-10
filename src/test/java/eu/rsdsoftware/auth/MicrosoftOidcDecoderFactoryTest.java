package eu.rsdsoftware.auth;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.*;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.*;
import java.time.Instant;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.JwtException;
import static org.junit.jupiter.api.Assertions.*;

class MicrosoftOidcDecoderFactoryTest {
    private static final String PERSONAL="9188040d-6c67-4c5b-b112-36a304b66dad";
    private static final String COMPANY="11111111-2222-3333-4444-555555555555";
    private final RSAKey key=new RSAKeyGenerator(2048).keyID("test-key").generate();
    MicrosoftOidcDecoderFactoryTest() throws JOSEException { }

    private org.springframework.security.oauth2.client.registration.ClientRegistration registration() {
        return new ProviderRegistrations(TestSigningMaterial.settings(false),new ProviderConfigurationTest().configured()
            .withProperty("rsds.auth.providers.microsoft.tenant","common")).findByRegistrationId("microsoft");
    }
    private String token(String tenant,String issuer,String audience,Instant expires,RSAKey signing) throws Exception {
        var claims=new JWTClaimsSet.Builder().issuer(issuer).subject("same-subject").audience(audience)
            .issueTime(Date.from(Instant.now().minusSeconds(10))).expirationTime(Date.from(expires));
        if(tenant!=null) claims.claim("tid",tenant);
        var jwt=new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID("test-key").build(),claims.build());
        jwt.sign(new RSASSASigner(signing)); return jwt.serialize();
    }
    private MicrosoftOidcDecoderFactory factory(String keyIssuer) throws Exception {
        var json=new LinkedHashMap<>(key.toPublicJWK().toJSONObject()); json.put("issuer",keyIssuer);
        String document=com.nimbusds.jose.util.JSONObjectUtils.toJSONString(Map.of("keys",List.of(json)));
        return new MicrosoftOidcDecoderFactory(new MicrosoftSigningKeys(()->document));
    }
    @Test void acceptsPersonalAndMultipleOrganizationsAndPreservesIssuer() throws Exception {
        var client=registration();
        assertEquals("https://login.microsoftonline.com/common/oauth2/v2.0/authorize",client.getProviderDetails().getAuthorizationUri());
        var decoder=factory("https://login.microsoftonline.com/{tenantid}/v2.0").createDecoder(client);
        for(String tenant:List.of(PERSONAL,COMPANY,"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")) {
            String issuer="https://login.microsoftonline.com/"+tenant+"/v2.0";
            assertEquals(issuer,decoder.decode(token(tenant,issuer,client.getClientId(),Instant.now().plusSeconds(300),key)).getIssuer().toString());
        }
    }
    @Test void rejectsMissingMalformedMismatchedAndUntrustedIssuers() throws Exception {
        var client=registration(); var decoder=factory("https://login.microsoftonline.com/{tenantid}/v2.0").createDecoder(client);
        String issuer="https://login.microsoftonline.com/"+PERSONAL+"/v2.0";
        for(String tenant:Arrays.asList(null,"common","../attacker","1-1-1-1-1",COMPANY))
            assertThrows(JwtException.class,()->decoder.decode(token(tenant,issuer,client.getClientId(),Instant.now().plusSeconds(300),key)));
        for(String bad:List.of("https://attacker.invalid/"+PERSONAL+"/v2.0",issuer+"/","http://login.microsoftonline.com/"+PERSONAL+"/v2.0"))
            assertThrows(JwtException.class,()->decoder.decode(token(PERSONAL,bad,client.getClientId(),Instant.now().plusSeconds(300),key)));
        assertThrows(JwtException.class,()->decoder.decode("not-a-jwt"));
        var unsigned=new PlainJWT(new JWTClaimsSet.Builder().issuer(issuer).claim("tid",PERSONAL).build()).serialize();
        assertThrows(JwtException.class,()->decoder.decode(unsigned));
    }
    @Test void rejectsWrongAudienceExpiredTokenAndForgedSignature() throws Exception {
        var client=registration(); var decoder=factory("https://login.microsoftonline.com/{tenantid}/v2.0").createDecoder(client);
        String issuer="https://login.microsoftonline.com/"+PERSONAL+"/v2.0";
        assertThrows(JwtException.class,()->decoder.decode(token(PERSONAL,issuer,"another-app",Instant.now().plusSeconds(300),key)));
        assertThrows(JwtException.class,()->decoder.decode(token(PERSONAL,issuer,client.getClientId(),Instant.now().minusSeconds(300),key)));
        var forged=new RSAKeyGenerator(2048).generate();
        assertThrows(JwtException.class,()->decoder.decode(token(PERSONAL,issuer,client.getClientId(),Instant.now().plusSeconds(300),forged)));
    }
    @Test void restrictsSigningKeyIssuerEvenWhenSignatureIsValid() throws Exception {
        var client=registration(); String issuer="https://login.microsoftonline.com/"+PERSONAL+"/v2.0";
        String jwt=token(PERSONAL,issuer,client.getClientId(),Instant.now().plusSeconds(300),key);
        assertDoesNotThrow(()->factory(issuer).createDecoder(client).decode(jwt));
        assertThrows(JwtException.class,()->factory("https://login.microsoftonline.com/"+COMPANY+"/v2.0").createDecoder(client).decode(jwt));
        assertThrows(JwtException.class,()->factory("").createDecoder(client).decode(jwt));
    }
    @Test void springOidcProviderRetainsStateAndNonceChecks() throws Exception {
        var client=registration(); String issuer="https://login.microsoftonline.com/"+PERSONAL+"/v2.0";
        String encoded=token(PERSONAL,issuer,client.getClientId(),Instant.now().plusSeconds(300),key);
        var provider=new org.springframework.security.oauth2.client.oidc.authentication.OidcAuthorizationCodeAuthenticationProvider(
            request -> org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse.withToken("fixture-access-token")
                .tokenType(org.springframework.security.oauth2.core.OAuth2AccessToken.TokenType.BEARER)
                .additionalParameters(Map.of("id_token",encoded)).build(),
            request -> new org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser(List.of(new org.springframework.security.core.authority.SimpleGrantedAuthority("ROLE_USER")),request.getIdToken()));
        provider.setJwtDecoderFactory(factory("https://login.microsoftonline.com/{tenantid}/v2.0"));
        var authorization=org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest.authorizationCode()
            .authorizationUri(client.getProviderDetails().getAuthorizationUri()).clientId(client.getClientId())
            .redirectUri(client.getRedirectUri()).scopes(Set.of("openid","profile")).state("expected-state").build();
        var response=org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponse.success("fixture-code")
            .redirectUri(client.getRedirectUri()).state("expected-state").build();
        var exchange=new org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationExchange(authorization,response);
        assertTrue(provider.authenticate(new org.springframework.security.oauth2.client.authentication.OAuth2LoginAuthenticationToken(client,exchange)).isAuthenticated());
        var wrongState=org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponse.success("fixture-code")
            .redirectUri(client.getRedirectUri()).state("wrong-state").build();
        assertThrows(org.springframework.security.oauth2.core.OAuth2AuthenticationException.class,()->provider.authenticate(
            new org.springframework.security.oauth2.client.authentication.OAuth2LoginAuthenticationToken(client,
                new org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationExchange(authorization,wrongState))));
        var nonceRequest=org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest.from(authorization)
            .attributes(attributes->attributes.put("nonce","original-nonce")).build();
        assertThrows(org.springframework.security.oauth2.core.OAuth2AuthenticationException.class,()->provider.authenticate(
            new org.springframework.security.oauth2.client.authentication.OAuth2LoginAuthenticationToken(client,
                new org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationExchange(nonceRequest,response))));
    }
}
