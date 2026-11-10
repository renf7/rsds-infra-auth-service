package eu.rsdsoftware.auth;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.proc.*;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import java.text.ParseException;
import java.util.regex.Pattern;
import org.springframework.security.oauth2.client.oidc.authentication.*;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.*;

/** Tenant-independent Microsoft login with tenant- and signing-key-scoped trust. */
public final class MicrosoftOidcDecoderFactory implements JwtDecoderFactory<ClientRegistration> {
    static final String AUTHORITY="https://login.microsoftonline.com/";
    private static final Pattern TENANT=Pattern.compile("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}");
    private final OidcIdTokenDecoderFactory standard=new OidcIdTokenDecoderFactory();
    private final MicrosoftSigningKeys keys;

    public MicrosoftOidcDecoderFactory() { this(new MicrosoftSigningKeys()); }
    MicrosoftOidcDecoderFactory(MicrosoftSigningKeys keys) { this.keys=keys; }

    static boolean validTenant(String value) { return value!=null && TENANT.matcher(value).matches(); }

    @Override public JwtDecoder createDecoder(ClientRegistration registration) {
        if(!"microsoft".equals(registration.getRegistrationId())
                || !(AUTHORITY+"common/v2.0").equals(registration.getProviderDetails().getIssuerUri()))
            return standard.createDecoder(registration);
        return token -> decode(registration,token);
    }

    private Jwt decode(ClientRegistration registration,String token) {
        try {
            // Untrusted claims only select a strict issuer expectation; never a URL to fetch.
            var claims=SignedJWT.parse(token).getJWTClaimsSet();
            String tenant=claims.getStringClaim("tid");
            if(!validTenant(tenant)) throw new BadJwtException("Invalid Microsoft tenant");
            String issuer=AUTHORITY+tenant+"/v2.0";
            if(!issuer.equals(claims.getIssuer())) throw new BadJwtException("Microsoft issuer does not match tenant");
            var processor=new DefaultJWTProcessor<SecurityContext>();
            processor.setJWSKeySelector(new JWSVerificationKeySelector<>(JWSAlgorithm.RS256,(selector,context) ->
                keys.select(selector,issuer)));
            var decoder=new NimbusJwtDecoder(processor);
            var tenantClient=ClientRegistration.withClientRegistration(registration).issuerUri(issuer).build();
            decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(
                new OidcIdTokenValidator(tenantClient),new JwtTimestampValidator()));
            // Signature, audience/azp, required claims, issuer and timestamps are validated here.
            // Spring's OIDC authentication provider retains state and nonce validation afterward.
            return decoder.decode(token);
        } catch(ParseException failure) {
            throw new BadJwtException("Malformed Microsoft ID token",failure);
        }
    }
}
