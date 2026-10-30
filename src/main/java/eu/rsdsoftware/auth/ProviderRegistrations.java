package eu.rsdsoftware.auth;
import java.util.*;
import org.springframework.core.env.Environment;
import org.springframework.security.oauth2.client.registration.*;
import org.springframework.security.oauth2.core.*;
import org.springframework.stereotype.Component;

@Component
public final class ProviderRegistrations implements ClientRegistrationRepository,Iterable<ClientRegistration> {
    public static final List<String> PROVIDERS=List.of("facebook","microsoft","google","apple","github");
    private final Map<String,ClientRegistration> registrations;
    public ProviderRegistrations(AuthSettings settings,Environment env) {
        var result=new LinkedHashMap<String,ClientRegistration>();
        for(String id:PROVIDERS) {
            String prefix="rsds.auth.providers."+id+".";
            String clientId=settings.local()?"local-"+id:env.getProperty(prefix+"client-id");
            if(clientId==null || clientId.isBlank()) continue;
            String secret=settings.local()?"local-fixture-secret":id.equals("apple")?"generated-at-token-exchange":env.getRequiredProperty(prefix+"client-secret");
            var builder=ClientRegistration.withRegistrationId(id).clientId(clientId).clientSecret(secret)
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri(settings.local()?"{baseUrl}/api/auth/login/oauth2/code/{registrationId}":env.getRequiredProperty("rsds.auth.public-base-url")+"/api/auth/login/oauth2/code/"+id)
                .clientName(id);
            boolean oidc=Set.of("google","microsoft","apple").contains(id);
            if(settings.local()) {
                String base=settings.idpBase()+"/"+id;
                builder.authorizationUri(base+"/authorize").tokenUri(base+"/token").userInfoUri(base+"/userinfo").userNameAttributeName(oidc?"sub":"id");
                if(oidc) builder.issuerUri(base).jwkSetUri(base+"/jwks").scope("openid","profile","email");
                else builder.scope(id.equals("github")?"read:user":"public_profile");
            } else switch(id) {
                case "google" -> builder.issuerUri("https://accounts.google.com").authorizationUri("https://accounts.google.com/o/oauth2/v2/auth")
                    .tokenUri("https://oauth2.googleapis.com/token").jwkSetUri("https://www.googleapis.com/oauth2/v3/certs")
                    .userInfoUri("https://openidconnect.googleapis.com/v1/userinfo").userNameAttributeName("sub").scope("openid","profile","email");
                case "microsoft" -> {
                    String tenant=env.getRequiredProperty(prefix+"tenant");
                    if(!tenant.matches("[0-9a-fA-F-]{36}")) throw new IllegalArgumentException("Microsoft requires an explicit tenant UUID");
                    String base="https://login.microsoftonline.com/"+tenant;
                    builder.issuerUri(base+"/v2.0").authorizationUri(base+"/oauth2/v2.0/authorize").tokenUri(base+"/oauth2/v2.0/token")
                        .jwkSetUri(base+"/discovery/v2.0/keys").userInfoUri("https://graph.microsoft.com/oidc/userinfo").userNameAttributeName("sub").scope("openid","profile","email");
                }
                case "apple" -> builder.issuerUri("https://appleid.apple.com").authorizationUri("https://appleid.apple.com/auth/authorize")
                    .tokenUri("https://appleid.apple.com/auth/token").jwkSetUri("https://appleid.apple.com/auth/keys").userNameAttributeName("sub").scope("openid","name","email");
                case "github" -> builder.authorizationUri("https://github.com/login/oauth/authorize").tokenUri("https://github.com/login/oauth/access_token")
                    .userInfoUri("https://api.github.com/user").userNameAttributeName("id").scope("read:user");
                case "facebook" -> {
                    String version=env.getRequiredProperty(prefix+"graph-version");
                    if(!version.matches("v[0-9]+\\.[0-9]+")) throw new IllegalArgumentException("Configure a supported Facebook Graph API version");
                    builder.authorizationUri("https://www.facebook.com/"+version+"/dialog/oauth").tokenUri("https://graph.facebook.com/"+version+"/oauth/access_token")
                        .userInfoUri("https://graph.facebook.com/"+version+"/me?fields=id,name").userNameAttributeName("id").scope("public_profile");
                }
                default -> throw new IllegalStateException("Unsupported provider");
            }
            result.put(id,builder.build());
        }
        this.registrations=Map.copyOf(result);
    }
    @Override public ClientRegistration findByRegistrationId(String id) { return registrations.get(id); }
    @Override public Iterator<ClientRegistration> iterator() { return registrations.values().iterator(); }
    public List<Map<String,Object>> availability() {
        return PROVIDERS.stream().map(id -> Map.<String,Object>of("id",id,"enabled",registrations.containsKey(id))).toList();
    }
}

