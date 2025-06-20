package dev.cloudnative.learning.tlshotreload.x509;

import javax.net.ssl.X509TrustManager;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

/**
 * A decorator for an {@link X509TrustManager} that adds extensive logging capabilities.
 * <p>
 * This class wraps an existing {@code X509TrustManager} and delegates all of its
 * method calls to the original manager. Its primary purpose is to intercept the
 * {@code checkClientTrusted} and {@code checkServerTrusted} calls to log the
 * certificate chains being presented for validation. It also logs the accepted
 * issuers. This is invaluable for debugging mTLS handshake issues by showing
 * exactly which certificates are being evaluated and which CAs are trusted.
 */
public class LoggingTrustManager implements X509TrustManager {
    private final X509TrustManager original;

    public LoggingTrustManager(X509TrustManager original) {
        this.original = original;
    }

    /**
     * Logs the provided client certificate chain before delegating the trust check
     * to the original trust manager.
     *
     * @param chain    the peer certificate chain presented by the client.
     * @param authType the authentication type based on the client certificate.
     * @throws CertificateException if the certificate chain is not trusted
     *                              by the original trust manager.
     */
    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        CertificateLogger.logCertificates("CLIENT", chain);
        original.checkClientTrusted(chain, authType);
    }

    /**
     * Logs the provided server certificate chain before delegating the trust check
     * to the original trust manager.
     *
     * @param chain    the peer certificate chain presented by the server.
     * @param authType the key exchange algorithm used.
     * @throws CertificateException if the certificate chain is not trusted
     *                              by the original trust manager.
     */
    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        CertificateLogger.logCertificates("SERVER", chain);
        original.checkServerTrusted(chain, authType);
    }

    /**
     * Retrieves the list of accepted certificate issuers from the original trust manager
     * and logs their details for debugging purposes.
     *
     * @return a non-null (possibly empty) array of acceptable CA issuer certificates.
     */
    @Override
    public X509Certificate[] getAcceptedIssuers() {
        return original.getAcceptedIssuers();
    }
}
