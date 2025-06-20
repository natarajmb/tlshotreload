package dev.cloudnative.learning.tlshotreload;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ssl.SslBundle;
import org.springframework.boot.ssl.SslBundles;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestClient;

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;


/**
 * REST controller for demonstrating and testing SSL hot reload capabilities.
 * Provides endpoints to display application information, SSL certificate details,
 * and internal API calls.
 */
@RestController
public class TestController {

    private final SslBundles sslBundles;
    private final RestClient restClient;
    @Value("${spring.application.name}")
    private String applicationName;

    /**
     * Constructs a new TestController with the necessary dependencies.
     *
     * @param sslBundles An instance of {@link SslBundles} for accessing SSL certificate bundles.
     * @param restClient An instance of {@link RestClient} for making internal HTTP calls.
     */
    public TestController(SslBundles sslBundles, RestClient restClient) {
        this.sslBundles = sslBundles;
        this.restClient = restClient;
    }

    /**
     * Handles requests to the root path ("/") and provides basic application information.
     *
     * @return A {@link ResponseEntity} containing a map with a welcome message and a timestamp.
     */
    @GetMapping("/")
    public ResponseEntity<Map<String, Object>> home() {
        Map<String, Object> response = new HashMap<>();
        response.put("message", "SSL Hot Reload Demo");
        response.put("timestamp", System.currentTimeMillis());
        return ResponseEntity.ok(response);
    }

    /**
     * Retrieves and displays detailed information about the SSL certificate used by the application.
     * It attempts to find the certificate associated with the "self" SSL bundle.
     * If an alias is not explicitly configured, it tries to find the first private key alias in the keystore.
     *
     * @return A {@link ResponseEntity} containing a map with SSL certificate details (subject, issuer,
     *         serial number, validity dates) or an error message if the bundle is not found or
     *         certificate information cannot be retrieved. It also indicates if the bundle is active.
     */
    @GetMapping("/ssl-info")
    public ResponseEntity<Map<String, Object>> getSslInfo() {
        Map<String, Object> response = new HashMap<>();

        try {
            SslBundle sslBundle = sslBundles.getBundle("self");

            if (sslBundle != null && sslBundle.getStores().getKeyStore() != null) {
                // Find the alias in a more robust way
                String alias = findKeyAlias(sslBundle);
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

    /**
     * Makes an internal HTTP GET request to the "/api/health" endpoint using the configured RestClient.
     * This demonstrates how the application can make calls to its own or other services, potentially
     * leveraging the configured SSL context.
     *
     * @param request The incoming {@link HttpServletRequest}.
     * @return The response body from the "/api/health" endpoint.
     */
    @GetMapping("/api/test")
    public String test(HttpServletRequest request) {
        return restClient.get().uri("/api/health").retrieve().body(String.class);
    }

    /**
     * Provides a simple health check endpoint for the application.
     *
     * @return A string indicating that the application is running and mTLS is enabled.
     */
    @GetMapping("/api/health")
    public String health() {
        return String.format("Reached %s, and is running with mTLS enabled", applicationName);
    }

    /**
     * Finds the private key alias from the SslBundle.
     * It first checks for a configured alias. If not found, it iterates
     * the keystore to find the first available private key alias.
     *
     * @param sslBundle The SslBundle to inspect.
     * @return The alias of the private key, or null if not found.
     * @throws KeyStoreException if the keystore has not been loaded.
     */
    private String findKeyAlias(SslBundle sslBundle) throws KeyStoreException {
        // First, prefer the explicitly configured alias
        String configuredAlias = sslBundle.getKey().getAlias();
        if (configuredAlias != null) {
            return configuredAlias;
        }

        // If no alias is configured, search the keystore for a private key
        KeyStore keyStore = sslBundle.getStores().getKeyStore();
        Enumeration<String> aliases = keyStore.aliases();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            if (keyStore.isKeyEntry(alias)) {
                // Return the first private key alias we find
                return alias;
            }
        }

        // Return null if no private key alias was found
        return null;
    }

}