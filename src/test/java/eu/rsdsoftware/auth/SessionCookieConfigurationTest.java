package eu.rsdsoftware.auth;

import static org.junit.jupiter.api.Assertions.*;
import java.util.Properties;
import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.boot.context.properties.source.MapConfigurationPropertySource;
import org.springframework.boot.web.server.autoconfigure.ServerProperties;

class SessionCookieConfigurationTest {
    @Test void productionForcesSecureWhileLocalUsesRequestAwareContainerDefault() throws Exception {
        Properties properties=new Properties();
        try(var input=getClass().getResourceAsStream("/application.properties")) { properties.load(input); }
        assertEquals(Boolean.TRUE,bind(properties).getServlet().getSession().getCookie().getSecure());
        try(var input=getClass().getResourceAsStream("/application-local.properties")) { properties.load(input); }
        assertNull(bind(properties).getServlet().getSession().getCookie().getSecure());
        assertEquals(Boolean.TRUE,bind(properties).getServlet().getSession().getCookie().getHttpOnly());
    }

    private ServerProperties bind(Properties properties) {
        var values=new java.util.HashMap<String,Object>();
        properties.forEach((key,value)->values.put(key.toString(),value));
        return new Binder(new MapConfigurationPropertySource(values)).bind("server",ServerProperties.class).get();
    }
}
