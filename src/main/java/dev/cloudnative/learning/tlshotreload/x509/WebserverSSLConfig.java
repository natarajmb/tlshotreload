package dev.cloudnative.learning.tlshotreload.x509;

import org.springframework.boot.ssl.SslBundle;
import org.springframework.boot.ssl.SslBundles;
import org.springframework.boot.web.embedded.tomcat.TomcatServletWebServerFactory;
import org.springframework.boot.web.server.WebServerFactoryCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableScheduling;

@Configuration
@EnableScheduling
public class WebserverSSLConfig {

    private final SslBundles sslBundles;

    public WebserverSSLConfig(SslBundles sslBundles) {
        this.sslBundles = sslBundles;
    }

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