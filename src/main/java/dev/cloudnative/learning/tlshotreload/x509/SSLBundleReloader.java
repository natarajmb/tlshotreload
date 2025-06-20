package dev.cloudnative.learning.tlshotreload.x509;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.support.DefaultSingletonBeanRegistry;
import org.springframework.boot.ssl.SslBundles;
import org.springframework.context.ApplicationContext;
import org.springframework.stereotype.Component;

/**
 * Manages the hot-reloading of Spring beans that depend on an SSL bundle.
 * <p>
 * This component listens for update events on a specific {@link SslBundles}
 * instance (in this case, the one named "remote"). When an update is detected,
 * it programmatically destroys and recreates the dependent bean (e.g., "restClient").
 * This powerful mechanism allows the application to pick up new SSL certificates
 * and keys without requiring a full restart.
 */
@Component
public class SSLBundleReloader {

    private final Logger logger = LoggerFactory.getLogger(SSLBundleReloader.class);
    private SslBundles sslBundles;
    private ApplicationContext context;

    /**
     * Initializes the reloader and registers the update handler.
     * <p>
     * This method is invoked by Spring for dependency injection. It stores the
     * necessary context and immediately registers a handler to listen for updates
     * on the "remote" SSL bundle.
     *
     * @param sslBundles The Spring Boot service for managing SSL bundles.
     * @param context    The application context, used to access the underlying bean factory.
     */
    @Autowired
    public void SslBundleReloader(SslBundles sslBundles,
                                  ApplicationContext context) {
        this.sslBundles = sslBundles;
        this.context = context;
        registerUpdateHandler();
    }

    /**
     * Registers a callback with the {@link SslBundles} service.
     * <p>
     * The handler is registered specifically for the "remote" bundle. When this
     * bundle is updated (e.g., its underlying file changes), the provided
     * lambda expression, which calls {@link #reloadRestClient()}, is executed.
     */
    private void registerUpdateHandler() {
        sslBundles.addBundleUpdateHandler("remote", bundle -> reloadRestClient());
    }

    /**
     * Reloads the "restClient" bean to apply the updated SSL configuration.
     * <p>
     * This method performs a manual manipulation of the Spring bean lifecycle:
     * <ol>
     *   <li>It accesses the underlying singleton bean registry from the application context.</li>
     *   <li>It explicitly destroys the existing singleton instance of the "restClient" bean.</li>
     *   <li>It then requests a new instance of "restClient" from the context, which triggers
     *       the original {@code @Bean} definition method, creating a new client with the
     *       updated SSL bundle.</li>
     *   <li>The new instance is registered back into the singleton registry.</li>
     * </ol>
     * <b>Note:</b> This direct manipulation of the bean registry is a powerful technique
     * but should be used with caution as it can have side effects in complex applications.
     */
    public void reloadRestClient() {
        DefaultSingletonBeanRegistry registry =
                (DefaultSingletonBeanRegistry) context.getAutowireCapableBeanFactory();

        // Destroy existing bean
        registry.destroySingleton("restClient");

        // Recreate using original bean definition
        registry.registerSingleton("restClient", context.getBean("restClient"));

        logger.info("Reloaded Remote SSL Bundles");
    }
}