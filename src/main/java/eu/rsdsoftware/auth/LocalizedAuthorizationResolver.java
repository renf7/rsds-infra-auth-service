package eu.rsdsoftware.auth;
import jakarta.servlet.http.HttpServletRequest;
import java.util.Set;
import org.springframework.security.oauth2.client.web.*;
import org.springframework.security.oauth2.core.endpoint.*;

/** Only two fixed return routes are accepted; no browser-supplied redirect URL is used. */
public final class LocalizedAuthorizationResolver implements OAuth2AuthorizationRequestResolver {
    private final DefaultOAuth2AuthorizationRequestResolver delegate;
    public LocalizedAuthorizationResolver(ProviderRegistrations providers,AuthSettings settings) {
        delegate=new DefaultOAuth2AuthorizationRequestResolver(providers,"/api/auth/oauth2/authorization");
        delegate.setAuthorizationRequestCustomizer(builder -> builder.attributes(attributes -> {
            String id=(String)attributes.get(OAuth2ParameterNames.REGISTRATION_ID);
            if(Set.of("google","microsoft","github").contains(id)) OAuth2AuthorizationRequestCustomizers.withPkce().accept(builder);
            if("apple".equals(id)) builder.additionalParameters(parameters -> parameters.put("response_mode","form_post"));
            if(settings.fixtureProviders()) builder.authorizationUri("/__test/idp/"+id+"/authorize");
        }));
    }
    private OAuth2AuthorizationRequest remember(HttpServletRequest request,OAuth2AuthorizationRequest authorization) {
        if(authorization!=null) request.getSession(true).setAttribute("uiLanguage","pl".equals(request.getParameter("lang"))?"pl":"en");
        return authorization;
    }
    @Override public OAuth2AuthorizationRequest resolve(HttpServletRequest request) { return remember(request,delegate.resolve(request)); }
    @Override public OAuth2AuthorizationRequest resolve(HttpServletRequest request,String id) { return remember(request,delegate.resolve(request,id)); }
    public static boolean polishReturn(HttpServletRequest request) {
        var session=request.getSession(false);
        return session!=null && "pl".equals(session.getAttribute("uiLanguage"));
    }
}
