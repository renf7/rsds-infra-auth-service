package eu.rsdsoftware.auth;
import jakarta.servlet.http.*;
import java.util.*;
import org.springframework.http.*;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

@RestController
@RequestMapping("/api/auth")
public final class AuthController {
    private final IdentityService identities;
    private final RefreshService refresh;
    private final SessionCookies cookies;
    private final TokenService tokens;
    private final ProviderRegistrations providers;
    @edu.umd.cs.findbugs.annotations.SuppressFBWarnings(value="EI_EXPOSE_REP2",justification="Injected cookie writer is shared deliberately; it only mutates the supplied servlet response, not controller state. No reference is exposed.")
    public AuthController(IdentityService identities,RefreshService refresh,SessionCookies cookies,TokenService tokens,ProviderRegistrations providers) {
        this.identities=identities; this.refresh=refresh; this.cookies=cookies; this.tokens=tokens; this.providers=providers;
    }
    @GetMapping("/providers") public Object providers() { return providers.availability(); }
    @GetMapping("/session") public Object session(@AuthenticationPrincipal Jwt jwt) {
        if(jwt==null) return Map.of("authenticated",false);
        var identity=identities.find(jwt.getSubject()).orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED));
        return Map.of("authenticated",true,"subject",identity.subject(),"name",identity.name(),"roles",identity.roles(),"provider",identity.provider());
    }
    @GetMapping("/me") public IdentityService.Identity me(@AuthenticationPrincipal Jwt jwt) {
        return identities.find(jwt.getSubject()).orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED));
    }
    @GetMapping("/csrf") public Object csrf(CsrfToken token) { return Map.of("token",token.getToken()); }
    @GetMapping("/.well-known/jwks.json") public Object jwks() { return tokens.jwks(); }
    @PostMapping("/refresh") public ResponseEntity<Void> rotate(HttpServletRequest request,HttpServletResponse response) {
        var rotated=refresh.rotate(SessionCookies.read(request,"RSDS_REFRESH"));
        if(rotated.isEmpty()) { cookies.clear(response); return ResponseEntity.status(401).build(); }
        var identity=identities.find(rotated.get().subject()).orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED));
        cookies.issue(response,tokens.issue(identity),rotated.get().token());
        return ResponseEntity.noContent().build();
    }
    @PostMapping("/logout") public ResponseEntity<Void> logout(HttpServletRequest request,HttpServletResponse response) {
        refresh.revoke(SessionCookies.read(request,"RSDS_REFRESH")); cookies.clear(response);
        var session=request.getSession(false); if(session!=null) session.invalidate();
        return ResponseEntity.noContent().build();
    }
}

