package eu.rsdsoftware.auth;
import jakarta.servlet.http.*;
import org.springframework.http.*;
import org.springframework.stereotype.Component;
@Component
public final class SessionCookies {
    private final AuthSettings settings;
    public SessionCookies(AuthSettings settings) { this.settings=settings; }
    public static String read(HttpServletRequest request,String name) {
        if(request.getCookies()!=null) for(var cookie:request.getCookies()) if(name.equals(cookie.getName())) return cookie.getValue();
        return null;
    }
    private void set(HttpServletResponse response,String name,String value,String path,long lifetime) {
        response.addHeader(HttpHeaders.SET_COOKIE,ResponseCookie.from(name,value).path(path).httpOnly(true)
            .secure(!settings.local()).sameSite("Lax").maxAge(lifetime).build().toString());
    }
    public void issue(HttpServletResponse response,String access,String refresh) {
        set(response,"RSDS_ACCESS",access,"/",300); set(response,"RSDS_REFRESH",refresh,"/api/auth",604800);
    }
    public void clear(HttpServletResponse response) {
        set(response,"RSDS_ACCESS","","/",0); set(response,"RSDS_REFRESH","","/api/auth",0);
        clearPending(response);
    }
    public void pending(HttpServletResponse response,String flow) {set(response,"RSDS_PENDING",flow,"/api/auth",600);}
    public void clearPending(HttpServletResponse response) {set(response,"RSDS_PENDING","","/api/auth",0);}
}

