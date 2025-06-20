package dev.cloudnative.learning.tlshotreload.x509;

import javax.net.ssl.X509KeyManager;
import java.net.Socket;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

public class LoggingKeyManager implements X509KeyManager {

    private final X509KeyManager original;

    public LoggingKeyManager(X509KeyManager original) {
        this.original = original;
    }

    @Override
    public String chooseClientAlias(String[] keyType, Principal[] issuers, Socket socket) {
        return original.chooseClientAlias(keyType, issuers, socket);
    }

    @Override
    public X509Certificate[] getCertificateChain(String alias) {
        X509Certificate[] chain = original.getCertificateChain(alias);
        CertificateLogger.logCertificates("CLIENT", chain);
        return chain;
    }

    @Override
    public String[] getClientAliases(String keyType, Principal[] issuers) {
        return new String[0];
    }

    @Override
    public String[] getServerAliases(String keyType, Principal[] issuers) {
        return new String[0];
    }

    @Override
    public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket) {
        return "";
    }

    @Override
    public PrivateKey getPrivateKey(String alias) {
        return null;
    }
}
