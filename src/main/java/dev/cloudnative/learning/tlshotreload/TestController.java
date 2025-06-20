package dev.cloudnative.learning.tlshotreload;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ssl.SslBundle;
import org.springframework.boot.ssl.SslBundles;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestClient;

import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;

@RestController
public class TestController {

    private final SslBundles sslBundles;
    private final RestClient restClient;
    @Value("${spring.application.name}")
    private String applicationName;

    public TestController(SslBundles sslBundles, RestClient restClient) {
        this.sslBundles = sslBundles;
        this.restClient = restClient;
    }

    @GetMapping("/")
    public ResponseEntity<Map<String, Object>> home() {
        Map<String, Object> response = new HashMap<>();
        response.put("message", "SSL Hot Reload Demo");
        response.put("timestamp", System.currentTimeMillis());
        return ResponseEntity.ok(response);
    }

    @GetMapping("/ssl-info")
    public ResponseEntity<Map<String, Object>> getSslInfo() {
        Map<String, Object> response = new HashMap<>();

        try {
            SslBundle sslBundle = sslBundles.getBundle("self");

            if (sslBundle != null && sslBundle.getStores().getKeyStore() != null) {
                // Get certificate information
                String alias = sslBundle.getKey().getAlias();
                X509Certificate cert = (X509Certificate) sslBundle.getStores().getKeyStore().getCertificate(alias);

                if (cert != null) {
                    response.put("subject", cert.getSubjectX500Principal().getName());
                    response.put("issuer", cert.getIssuerX500Principal().getName());
                    response.put("serialNumber", cert.getSerialNumber().toString());
                    response.put("notBefore", cert.getNotBefore());
                    response.put("notAfter", cert.getNotAfter());
                }
            }

            response.put("bundleActive", true);
        } catch (Exception e) {
            response.put("error", e.getMessage());
            response.put("bundleActive", false);
        }

        return ResponseEntity.ok(response);
    }

    @GetMapping("/api/test")
    public String test(HttpServletRequest request) {
        return restClient.get().uri("/api/health").retrieve().body(String.class);
    }

    @GetMapping("/api/health")
    public String health() {
        return String.format("Reached %s, and is running with mTLS enabled", applicationName);
    }
}