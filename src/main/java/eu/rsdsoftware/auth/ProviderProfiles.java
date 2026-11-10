package eu.rsdsoftware.auth;
import java.util.*;
import org.springframework.context.annotation.*;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.userinfo.*;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.OAuth2User;

@Configuration
public class ProviderProfiles {
    static String text(Object value) {return value instanceof String s?s:null;}
    public static ProviderProfile read(OAuth2AuthenticationToken login) {
        String provider=login.getAuthorizedClientRegistrationId();
        var user=Objects.requireNonNull(login.getPrincipal());
        String issuer=provider, external=user.getName();
        if(user instanceof OidcUser oidc) {
            issuer=Objects.requireNonNull(oidc.getIssuer()).toString(); external=oidc.getSubject();
        }
        String name=text(user.getAttribute("name"));
        if((name==null || name.isBlank()) && "github".equals(provider)) name=text(user.getAttribute("login"));
        if(name==null || name.isBlank()) name="User";
        // Incidental provider email claims are discarded, including verified ones.
        return new ProviderProfile(provider,issuer,external,name.substring(0,Math.min(name.length(),128)),null,false);
    }
    @Bean OAuth2UserService<OAuth2UserRequest,OAuth2User> providerUsers() {
        // Standard profile lookup only; no GitHub private email request.
        return new DefaultOAuth2UserService();
    }
}
