package dev.cloudnative.learning.tlshotreload.x509;

import javax.net.ssl.X509TrustManager;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

public class LoggingTrustManager implements X509TrustManager {
    private final X509TrustManager original;

    public LoggingTrustManager(X509TrustManager original) {
        this.original = original;
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        CertificateLogger.logCertificates("CLIENT", chain);
        original.checkClientTrusted(chain, authType);
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        CertificateLogger.logCertificates("SERVER", chain);
        original.checkServerTrusted(chain, authType);
    }

    @Override
    public X509Certificate[] getAcceptedIssuers() {
        return original.getAcceptedIssuers();
    }
}
