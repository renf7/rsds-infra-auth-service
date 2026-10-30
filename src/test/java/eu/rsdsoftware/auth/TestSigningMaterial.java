package eu.rsdsoftware.auth;
import java.nio.file.*;
import java.security.*;
import java.util.*;
final class TestSigningMaterial {
    private static Path directory;
    static synchronized Path directory() {
        if(directory!=null) return directory;
        try {
            directory=Files.createTempDirectory("rsds-auth-test-");
            String password=UUID.randomUUID().toString();
            Path storePath=directory.resolve("test.p12");
            var process=new ProcessBuilder("keytool","-genkeypair","-alias","auth","-keyalg","RSA","-keysize","2048","-storetype","PKCS12","-keystore",storePath.toString(),"-storepass",password,"-dname","CN=rsds-auth-unit-only","-validity","2").redirectErrorStream(true).start();
            process.getInputStream().readAllBytes();
            if(process.waitFor()!=0) throw new IllegalStateException("Test key generation failed");
            var store=KeyStore.getInstance("PKCS12");
            try(var input=Files.newInputStream(storePath)) { store.load(input,password.toCharArray()); }
            byte[] key=store.getKey("auth",password.toCharArray()).getEncoded();
            Files.writeString(directory.resolve("private.pem"),"-----BEGIN PRIVATE KEY-----\n"+Base64.getMimeEncoder(64,new byte[]{10}).encodeToString(key)+"\n-----END PRIVATE KEY-----\n");
            Files.createDirectories(directory.resolve("trust"));
            Files.writeString(directory.resolve("trust/active.crt"),"-----BEGIN CERTIFICATE-----\n"+Base64.getMimeEncoder(64,new byte[]{10}).encodeToString(store.getCertificate("auth").getEncoded())+"\n-----END CERTIFICATE-----\n");
            return directory;
        } catch(Exception exception) { throw new IllegalStateException(exception); }
    }
    static AuthSettings settings(boolean local) {
        var path=directory();
        return new AuthSettings(local,"https://www.rsdsoftware.eu/auth","rsds-infra",path.resolve("private.pem").toString(),path.resolve("trust").toString(),"eu-central-1","test","http://localhost:8000","http://rsds-local-idp:9000");
    }
}

