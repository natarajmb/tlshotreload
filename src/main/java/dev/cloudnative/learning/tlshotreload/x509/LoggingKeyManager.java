package dev.cloudnative.learning.tlshotreload.x509;

import javax.net.ssl.X509KeyManager;
import java.net.Socket;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

/**
 * A decorator for an {@link X509KeyManager} that adds logging capabilities.
 * <p>
 * This class wraps an existing {@code X509KeyManager} and delegates all of its
 * method calls to the original manager. Its primary purpose is to intercept the
 * certificate chain retrieval process in {@link #getCertificateChain(String)}
 * to log the client certificates being used. This is invaluable for debugging
 * mTLS handshake issues.
 */
public class LoggingKeyManager implements X509KeyManager {

    private final X509KeyManager original;

    /**
     * Constructs a new LoggingKeyManager.
     *
     * @param original The original {@link X509KeyManager} to which all calls will be delegated.
     *                 Must not be null.
     */
    public LoggingKeyManager(X509KeyManager original) {
        this.original = original;
    }


    /**
     * Delegates to the original manager to choose a client alias.
     * {@inheritDoc}
     */
    @Override
    public String chooseClientAlias(String[] keyType, Principal[] issuers, Socket socket) {
        return original.chooseClientAlias(keyType, issuers, socket);
    }

    /**
     * Retrieves the certificate chain from the original manager and logs it.
     * This is the primary logging point of this decorator.
     * {@inheritDoc}
     */
    @Override
    public X509Certificate[] getCertificateChain(String alias) {
        X509Certificate[] chain = original.getCertificateChain(alias);
        CertificateLogger.logCertificates("CLIENT", chain);
        return chain;
    }

    /**
     * Delegates to the original manager to get the list of client aliases.
     * {@inheritDoc}
     */
    @Override
    public String[] getClientAliases(String keyType, Principal[] issuers) {
        return new String[0];
    }


    /**
     * Delegates to the original manager to choose a server alias.
     * {@inheritDoc}
     */
    @Override
    public String[] getServerAliases(String keyType, Principal[] issuers) {
        return new String[0];
    }

    /**
     * Delegates to the original manager to get the list of server aliases.
     * {@inheritDoc}
     */
    @Override
    public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket) {
        return "";
    }

    /**
     * Delegates to the original manager to retrieve the private key.
     * {@inheritDoc}
     */
    @Override
    public PrivateKey getPrivateKey(String alias) {
        return null;
    }
}
