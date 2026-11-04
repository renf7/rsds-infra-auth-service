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
    private final EmailVerification verification;
    @edu.umd.cs.findbugs.annotations.SuppressFBWarnings(value="EI_EXPOSE_REP2",justification="Injected cookie writer is shared deliberately; it only mutates the supplied servlet response, not controller state. No reference is exposed.")
    public AuthController(IdentityService identities,RefreshService refresh,SessionCookies cookies,TokenService tokens,ProviderRegistrations providers,EmailVerification verification) {
        this.identities=identities; this.refresh=refresh; this.cookies=cookies; this.tokens=tokens; this.providers=providers; this.verification=verification;
    }
    @GetMapping("/providers") public Object providers() { return providers.availability(); }
    @GetMapping("/session") public Object session(@AuthenticationPrincipal Jwt jwt,HttpServletRequest request) {
        // Presence is only a recovery hint; refresh validates the credential separately.
        if(jwt==null) return Map.of("authenticated",false,"refreshAvailable",SessionCookies.read(request,"RSDS_REFRESH")!=null);
        var identity=identities.find(jwt.getSubject()).orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED));
        return Map.of("authenticated",true,"subject",identity.subject(),"name",identity.name(),"roles",identity.roles(),"email",identity.email(),"initials",identity.initials(),"avatarColor",identity.avatarColor());
    }
    @GetMapping("/me") public IdentityService.Identity me(@AuthenticationPrincipal Jwt jwt) {
        return identities.find(jwt.getSubject()).orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED));
    }
    @GetMapping("/csrf") public Object csrf(CsrfToken token) { return Map.of("token",token.getToken()); }
    @GetMapping("/email-verification") public Object verification(HttpServletRequest request) {
        try {return verification.status(SessionCookies.read(request,"RSDS_PENDING"));}
        catch(IllegalArgumentException invalid) {throw new ResponseStatusException(HttpStatus.UNAUTHORIZED,"Sign in again");}
    }
    public record EmailRequest(@jakarta.validation.constraints.NotBlank @jakarta.validation.constraints.Size(max=254) String email) {}
    public record CodeRequest(@jakarta.validation.constraints.NotBlank @jakarta.validation.constraints.Size(max=6) String code) {}
    @PostMapping("/email-code") public ResponseEntity<Void> emailCode(HttpServletRequest request,@jakarta.validation.Valid @RequestBody EmailRequest body) {
        try {verification.send(SessionCookies.read(request,"RSDS_PENDING"),body.email()); return ResponseEntity.noContent().build();}
        catch(IllegalArgumentException invalid) {throw new ResponseStatusException(HttpStatus.BAD_REQUEST,"Cannot send code; sign in again or wait");}
    }
    @PostMapping("/verify-email") public ResponseEntity<Void> verifyEmail(HttpServletRequest request,HttpServletResponse response,@jakarta.validation.Valid @RequestBody CodeRequest body) {
        try {
            var profile=verification.verify(SessionCookies.read(request,"RSDS_PENDING"),body.code());
            var identity=identities.login(profile.provider(),profile.issuer(),profile.externalSubject(),profile.name(),profile.email(),true);
            cookies.clearPending(response); cookies.issue(response,tokens.issue(identity),refresh.create(identity.subject()));
            return ResponseEntity.noContent().build();
        } catch(IllegalArgumentException invalid) {throw new ResponseStatusException(HttpStatus.BAD_REQUEST,"Invalid or expired code");}
    }
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

