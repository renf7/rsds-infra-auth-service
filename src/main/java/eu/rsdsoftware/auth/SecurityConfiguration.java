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
        var resolver=new LocalizedAuthorizationResolver(providers,settings);
        var tokenClient=new RestClientAuthorizationCodeTokenResponseClient();
        tokenClient.setParametersCustomizer(parameters -> {
            var appleRegistration=providers.findByRegistrationId("apple");
            if(appleRegistration!=null && appleRegistration.getClientId().equals(parameters.getFirst("client_id")))
                parameters.set("client_secret",apple.create());
        });
        var headers=new DefaultBearerTokenResolver();
        var csrfCookies=new CookieCsrfTokenRepository();
        csrfCookies.setCookieCustomizer(cookie -> cookie.secure(!settings.local()).sameSite("Lax"));
        return http.authorizeHttpRequests(auth -> auth.requestMatchers("/api/auth/me").authenticated().anyRequest().permitAll())
            .csrf(csrf -> configureAppleCallbackCsrf(csrf,csrfCookies))
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
                    boolean polishReturn=LocalizedAuthorizationResolver.polishReturn(request);
                    var session=request.getSession(false); if(session!=null) session.invalidate();
                    if(polishReturn) response.sendRedirect("/pl/?login=success");
                    else response.sendRedirect("/?login=success");
                }).failureHandler((request,response,exception) -> {
                    boolean polishReturn=LocalizedAuthorizationResolver.polishReturn(request);
                    var session=request.getSession(false); if(session!=null) session.invalidate();
                    cookies.clear(response);
                    if(polishReturn) response.sendRedirect("/pl/?login=failed");
                    else response.sendRedirect("/?login=failed");
                }))
            .oauth2ResourceServer(resource -> resource.jwt(jwt -> jwt.decoder(tokens.decoder())).bearerTokenResolver(request -> {
                String header=headers.resolve(request);
                if(header!=null) return header;
                return Set.of("/api/auth/me","/api/auth/session").contains(request.getRequestURI())?SessionCookies.read(request,"RSDS_ACCESS"):null;
            })).build();
    }
    /**
     * Apple's external form_post cannot send our synchronizer token. Only that exact POST
     * callback uses Spring's one-use OAuth state and OIDC nonce instead. All application
     * mutations retain CSRF validation. Negative callback and logout/refresh tests cover this.
     * Rule S4502 treats any custom matcher as disabling CSRF: this narrowly reviewed protocol
     * exception is intentional, not a global disable. Re-review by 2027-01-28.
     */
    @SuppressWarnings("java:S4502")
    private static void configureAppleCallbackCsrf(
            org.springframework.security.config.annotation.web.configurers.CsrfConfigurer<HttpSecurity> csrf,
            CookieCsrfTokenRepository cookies) {
        csrf.csrfTokenRepository(cookies).requireCsrfProtectionMatcher(request ->
            org.springframework.security.web.csrf.CsrfFilter.DEFAULT_CSRF_MATCHER.matches(request)
                && !("POST".equals(request.getMethod())
                    && "/api/auth/login/oauth2/code/apple".equals(request.getServletPath())));
    }
}

