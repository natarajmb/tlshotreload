package dev.cloudnative.learning.tlshotreload.x509;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.cert.X509Certificate;

/**
 * A utility class for logging the details of X.509 certificate chains.
 * <p>
 * This class provides a static method to print key information about each certificate
 * in a given chain to the application logs, which is highly useful for debugging
 * TLS handshake issues, such as verifying which certificates are being presented
 * or trusted.
 */
public class CertificateLogger {
    private static final Logger logger = LoggerFactory.getLogger(CertificateLogger.class);


    /**
     * Logs the details of a given certificate chain with a specified type identifier.
     * <p>
     * Iterates through the array of {@link X509Certificate}s and logs important
     * fields for each one, including Subject, Issuer, Serial Number, and validity period.
     * If the chain is null or empty, it logs an error.
     *
     * @param type  A string identifier for the type of certificate chain being logged
     *              (e.g., "Client", "Server"). This is used in the log output for clarity.
     * @param chain The array of {@link X509Certificate}s to be logged. Can be null or empty.
     */
    public static void logCertificates(String type, X509Certificate[] chain) {
        if (chain == null || chain.length == 0) {
            logger.error("No {} certificates found", type);
            return;
        }

        logger.info("===== {} CERTIFICATE CHAIN =====", type.toUpperCase());
        for (int i = 0; i < chain.length; i++) {
            X509Certificate cert = chain[i];
            logger.info("Certificate #{}:", i + 1);
            logger.info("  Subject: {}", cert.getSubjectX500Principal());
            logger.info("  Issuer: {}", cert.getIssuerX500Principal());
            logger.info("  Serial: {}", cert.getSerialNumber());
            logger.info("  Valid From: {}", cert.getNotBefore());
            logger.info("  Valid To: {}", cert.getNotAfter());
            logger.info("--------------------------------------");
        }
    }
}