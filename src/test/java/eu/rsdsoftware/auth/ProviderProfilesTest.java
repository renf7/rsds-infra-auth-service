package eu.rsdsoftware.auth;
import java.time.Instant;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import static org.junit.jupiter.api.Assertions.*;
class ProviderProfilesTest {
    private final List<SimpleGrantedAuthority> authorities=List.of(new SimpleGrantedAuthority("USER"));
    private ProviderProfile oidc(String provider,Map<String,Object> claims) {
        var values=new HashMap<String,Object>(claims); values.put("iss","https://issuer.example.test"); values.put("sub","immutable-sub"); values.put("name","Alice");
        var token=new OidcIdToken("test-token",Instant.now(),Instant.now().plusSeconds(60),values);
        return ProviderProfiles.read(new OAuth2AuthenticationToken(new DefaultOidcUser(authorities,token),authorities,provider));
    }
    @Test void googleAndAppleEmailClaimsAreNotIdentityInputs() {
        assertFalse(oidc("google",Map.of("email","alice@gmail.com","email_verified",true)).verified());
        assertFalse(oidc("google",Map.of("email","alice@example.test","email_verified",true,"hd","example.test")).verified());
        assertFalse(oidc("google",Map.of("email","alice@example.test","email_verified",true)).verified());
        assertFalse(oidc("google",Map.of("email","alice@gmail.com","email_verified",false)).verified());
        assertFalse(oidc("apple",Map.of("email","alice@privaterelay.appleid.com","email_verified","true")).verified());
    }
    @Test void microsoftEmailAndProfileVerificationAreNotOwnershipProof() {
        assertFalse(oidc("microsoft",Map.of("email","victim@example.test","email_verified",true)).verified());
        var user=new DefaultOAuth2User(authorities,Map.of("id","123","email","victim@example.test","verified",true),"id");
        assertFalse(ProviderProfiles.read(new OAuth2AuthenticationToken(user,authorities,"facebook")).verified());
    }
    @Test void missingAndMalformedEmailsAreDiscarded() {
        assertNull(oidc("apple",Map.of()).email());
        assertNull(oidc("google",Map.of("email","invalid","email_verified",true)).email());
        assertFalse(oidc("apple",Map.of("email","alice@example.test","email_verified","false")).verified());
    }
    @Test void githubEmailMarkersAreIgnored() {
        var user=new DefaultOAuth2User(authorities,Map.of("id","123","email","alice@example.test","app_verified_email",true),"id");
        assertFalse(ProviderProfiles.read(new OAuth2AuthenticationToken(user,authorities,"github")).verified());
    }
    @Test void githubUsernameSuppliesTheAccountNameWhenDisplayNameIsMissing() {
        var user=new DefaultOAuth2User(authorities,Map.of("id","123","login","rsdstest4"),"id");
        var profile=ProviderProfiles.read(new OAuth2AuthenticationToken(user,authorities,"github"));
        assertEquals("rsdstest4",profile.name());
        assertEquals("RS",AccountAvatar.initials(profile.name()));
    }
}
