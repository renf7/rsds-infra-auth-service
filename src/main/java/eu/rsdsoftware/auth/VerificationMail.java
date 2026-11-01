package eu.rsdsoftware.auth;
/** Production SMTP and a captured test adapter share the same challenge logic. */
@FunctionalInterface
public interface VerificationMail {void send(String email,String code);}
