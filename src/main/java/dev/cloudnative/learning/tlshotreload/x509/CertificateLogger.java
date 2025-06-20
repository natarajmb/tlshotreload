package dev.cloudnative.learning.tlshotreload.x509;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.cert.X509Certificate;

public class CertificateLogger {
    private static final Logger logger = LoggerFactory.getLogger(CertificateLogger.class);

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