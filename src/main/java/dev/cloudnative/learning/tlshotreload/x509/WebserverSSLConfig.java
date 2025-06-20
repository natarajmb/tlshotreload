package dev.cloudnative.learning.tlshotreload.x509;

import org.springframework.boot.ssl.SslBundle;
import org.springframework.boot.ssl.SslBundles;
import org.springframework.boot.web.embedded.tomcat.TomcatServletWebServerFactory;
import org.springframework.boot.web.server.WebServerFactoryCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Configures the embedded Tomcat web server to support SSL hot reloading.
 * <p>
 * This class provides a {@link WebServerFactoryCustomizer} that applies the
 * necessary SSL configuration to Tomcat, enabling it to automatically reload
 * its SSL context when the underlying certificate files change.
 * <p>
 */
@Configuration
public class WebserverSSLConfig {

    private final SslBundles sslBundles;

    public WebserverSSLConfig(SslBundles sslBundles) {
        this.sslBundles = sslBundles;
    }


    /**
     * Creates a {@link WebServerFactoryCustomizer} bean to configure the embedded Tomcat server for SSL.
     * <p>
     * This customizer performs two key actions:
     * <ol>
     *   <li>It registers the {@link SslBundles} instance with the Tomcat factory, making all
     *       configured bundles available to the server.</li>
     *   <li>It adds a connector customizer that sets the Tomcat-specific property
     *       {@code sslBundleReloadEnabled} to {@code "true"}, which activates the
     *       hot-reloading feature for the SSL bundle specified by the
     *       {@code server.ssl.bundle} property.</li>
     * </ol>
     *
     * @return A {@link WebServerFactoryCustomizer} that applies the SSL hot-reload configuration.
     */
    @Bean
    public WebServerFactoryCustomizer<TomcatServletWebServerFactory> sslBundleCustomizer() {
        return factory -> {
            // Get the SSL bundle
            SslBundle sslBundle = sslBundles.getBundle("self");

            // Configure SSL with hot reload support
            factory.setSslBundles(sslBundles);

            // Additional Tomcat SSL configuration if needed
            factory.addConnectorCustomizers(connector -> {
                // Enable SSL bundle hot reload
                connector.setProperty("sslBundleReloadEnabled", "true");
            });
        };
    }
}