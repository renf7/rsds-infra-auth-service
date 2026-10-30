package eu.rsdsoftware.auth;
import jakarta.servlet.http.*;
import java.util.Set;
import org.springframework.context.annotation.*;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.endpoint.RestClientAuthorizationCodeTokenResponseClient;
import org.springframework.security.oauth2.client.web.*;
import org.springframework.security.oauth2.core.endpoint.*;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.oauth2.server.resource.web.DefaultBearerTokenResolver;

@Configuration
public class SecurityConfiguration {
    @Bean SecurityFilterChain security(HttpSecurity http,ProviderRegistrations providers,AuthSettings settings,
            AppleClientSecret apple,IdentityService identities,TokenService tokens,RefreshService refresh,SessionCookies cookies) throws Exception {
        var resolver=new DefaultOAuth2AuthorizationRequestResolver(providers,"/api/auth/oauth2/authorization");
        resolver.setAuthorizationRequestCustomizer(builder -> builder.attributes(attributes -> {
            String id=(String)attributes.get(OAuth2ParameterNames.REGISTRATION_ID);
            if(Set.of("google","microsoft","github").contains(id)) OAuth2AuthorizationRequestCustomizers.withPkce().accept(builder);
            if("apple".equals(id)) builder.additionalParameters(parameters -> parameters.put("response_mode","form_post"));
            if(settings.local()) builder.authorizationUri("/__test/idp/"+id+"/authorize");
        }));
        var tokenClient=new RestClientAuthorizationCodeTokenResponseClient();
        tokenClient.setParametersCustomizer(parameters -> {
            var appleRegistration=providers.findByRegistrationId("apple");
            if(appleRegistration!=null && appleRegistration.getClientId().equals(parameters.getFirst("client_id")))
                parameters.set("client_secret",apple.create());
        });
        var headers=new DefaultBearerTokenResolver();
        var csrfCookies=CookieCsrfTokenRepository.withHttpOnlyFalse();
        csrfCookies.setCookieCustomizer(cookie -> cookie.secure(!settings.local()).sameSite("Lax"));
        return http.authorizeHttpRequests(auth -> auth.requestMatchers("/api/auth/me").authenticated().anyRequest().permitAll())
            .csrf(csrf -> csrf.csrfTokenRepository(csrfCookies)
                // Apple's response_mode=form_post is protected by Spring's one-use OAuth state/nonce validation.
                .ignoringRequestMatchers("/api/auth/login/oauth2/code/apple"))
            .requestCache(AbstractHttpConfigurer::disable).logout(AbstractHttpConfigurer::disable)
            .oauth2Login(oauth -> oauth.authorizationEndpoint(endpoint -> endpoint.authorizationRequestResolver(resolver))
                .redirectionEndpoint(endpoint -> endpoint.baseUri("/api/auth/login/oauth2/code/*"))
                .tokenEndpoint(endpoint -> endpoint.accessTokenResponseClient(tokenClient))
                .successHandler((request,response,authentication) -> {
                    var login=(OAuth2AuthenticationToken)authentication;
                    String provider=login.getAuthorizedClientRegistrationId();
                    var principal=java.util.Objects.requireNonNull(login.getPrincipal());
                    String issuer=principal instanceof OidcUser oidc?java.util.Objects.requireNonNull(oidc.getIssuer()).toString():provider;
                    String external=principal instanceof OidcUser oidc?oidc.getSubject():principal.getName();
                    String name=principal.getAttribute("name") instanceof String text?text.substring(0,Math.min(text.length(),128)):"User";
                    var identity=identities.login(provider,issuer,external,name);
                    cookies.issue(response,tokens.issue(identity),refresh.create(identity.subject()));
                    var session=request.getSession(false); if(session!=null) session.invalidate();
                    response.sendRedirect("/?login=success");
                }).failureHandler((request,response,exception) -> {
                    var session=request.getSession(false); if(session!=null) session.invalidate();
                    cookies.clear(response); response.sendRedirect("/?login=failed");
                }))
            .oauth2ResourceServer(resource -> resource.jwt(jwt -> jwt.decoder(tokens.decoder())).bearerTokenResolver(request -> {
                String header=headers.resolve(request);
                if(header!=null) return header;
                return Set.of("/api/auth/me","/api/auth/session").contains(request.getRequestURI())?SessionCookies.read(request,"RSDS_ACCESS"):null;
            })).build();
    }
}

