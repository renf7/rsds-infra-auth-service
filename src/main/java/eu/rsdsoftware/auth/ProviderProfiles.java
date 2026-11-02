package eu.rsdsoftware.auth;
import java.util.*;
import java.net.http.HttpClient;
import java.time.Duration;
import org.springframework.context.annotation.*;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.client.JdkClientHttpRequestFactory;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.userinfo.*;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.*;
import org.springframework.web.client.RestClient;

@Configuration
public class ProviderProfiles {
    static boolean yes(Object value) {return Boolean.TRUE.equals(value) || "true".equals(value);}
    static String text(Object value) {return value instanceof String s?s:null;}
    public static ProviderProfile read(OAuth2AuthenticationToken login) {
        String provider=login.getAuthorizedClientRegistrationId(); var user=Objects.requireNonNull(login.getPrincipal());
        String issuer=provider, external=user.getName(); Map<String,Object> claims=user.getAttributes();
        if(user instanceof OidcUser oidc) {issuer=Objects.requireNonNull(oidc.getIssuer()).toString(); external=oidc.getSubject(); claims=Objects.requireNonNull(oidc.getIdToken()).getClaims();}
        String email=text(claims.get("email")), name=text(user.getAttribute("name"));
        if(name==null) name="User";
        boolean verified=false;
        if(email!=null) {
            try {email=EmailAddress.normalize(email);} catch(IllegalArgumentException invalid) {email=null;}
        }
        if(email!=null) {
            verified=switch(provider) {
                case "google" -> yes(claims.get("email_verified")) && (email.endsWith("@gmail.com")
                    || email.substring(email.indexOf('@')+1).equals(text(claims.get("hd"))));
                case "apple" -> yes(claims.get("email_verified"));
                case "github" -> Boolean.TRUE.equals(claims.get("app_verified_email"));
                // Microsoft email claims and Facebook profile verification are not email-ownership proof.
                default -> false;
            };
        }
        return new ProviderProfile(provider,issuer,external,name.substring(0,Math.min(name.length(),128)),email,verified);
    }
    @Bean OAuth2UserService<OAuth2UserRequest,OAuth2User> providerUsers(AuthSettings settings) {
        var standard=new DefaultOAuth2UserService();
        var factory=new JdkClientHttpRequestFactory(HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build());
        factory.setReadTimeout(Duration.ofSeconds(10));
        var client=RestClient.builder().requestFactory(factory).build();
        return request->{
            var user=standard.loadUser(request);
            if(!"github".equals(request.getClientRegistration().getRegistrationId())) return user;
            String endpoint=settings.fixtureProviders()?settings.idpBase()+"/github/emails":"https://api.github.com/user/emails";
            var emails=client.get().uri(endpoint).headers(h->h.setBearerAuth(request.getAccessToken().getTokenValue()))
                .retrieve().body(new ParameterizedTypeReference<List<Map<String,Object>>>() {});
            var attributes=new HashMap<>(user.getAttributes()); attributes.put("app_verified_email",false);
            if(emails!=null) emails.stream().filter(e->Boolean.TRUE.equals(e.get("primary")) && Boolean.TRUE.equals(e.get("verified")))
                .findFirst().ifPresent(e->{attributes.put("email",e.get("email")); attributes.put("app_verified_email",true);});
            return new DefaultOAuth2User(user.getAuthorities(),attributes,request.getClientRegistration().getProviderDetails().getUserInfoEndpoint().getUserNameAttributeName());
        };
    }
}
