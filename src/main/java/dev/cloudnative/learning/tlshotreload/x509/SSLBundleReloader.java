package dev.cloudnative.learning.tlshotreload.x509;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.support.DefaultSingletonBeanRegistry;
import org.springframework.boot.ssl.SslBundles;
import org.springframework.context.ApplicationContext;
import org.springframework.stereotype.Component;

@Component
public class SSLBundleReloader {

    private final Logger logger = LoggerFactory.getLogger(SSLBundleReloader.class);
    private SslBundles sslBundles;
    private ApplicationContext context;

    @Autowired
    public void SslBundleReloader(SslBundles sslBundles,
                                  ApplicationContext context) {
        this.sslBundles = sslBundles;
        this.context = context;
        registerUpdateHandler();
    }

    private void registerUpdateHandler() {
        sslBundles.addBundleUpdateHandler("remote", bundle -> reloadRestClient());
    }

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