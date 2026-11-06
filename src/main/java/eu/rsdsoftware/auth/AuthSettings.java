package eu.rsdsoftware.auth;
import org.springframework.boot.context.properties.ConfigurationProperties;
@ConfigurationProperties("rsds.auth")
public record AuthSettings(boolean local, String issuer, String audience, String privateKey,
                           String publicCertificates, String region, String table, String dynamoEndpoint, String idpBase, String providerMode) {
    @org.springframework.boot.context.properties.bind.ConstructorBinding
    public AuthSettings {
        if(providerMode==null) providerMode=local?"fixture":"live";
        if(!java.util.Set.of("fixture","live").contains(providerMode) || (!local && "fixture".equals(providerMode)))
            throw new IllegalArgumentException("Provider mode must be live, or fixture with local infrastructure only");
    }
    public AuthSettings(boolean local,String issuer,String audience,String privateKey,String publicCertificates,String region,String table,String dynamoEndpoint,String idpBase) {
        this(local,issuer,audience,privateKey,publicCertificates,region,table,dynamoEndpoint,idpBase,null);
    }
    public boolean fixtureProviders() { return "fixture".equals(providerMode); }
}

