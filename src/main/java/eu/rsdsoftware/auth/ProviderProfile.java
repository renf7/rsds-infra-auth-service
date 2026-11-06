package eu.rsdsoftware.auth;
/** Data from a validated provider response; verified describes email ownership, not OAuth success. */
public record ProviderProfile(String provider,String issuer,String externalSubject,String name,String email,boolean verified) {}
