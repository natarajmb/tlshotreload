package dev.cloudnative.learning.tlshotreload;

import dev.cloudnative.learning.tlshotreload.x509.LoggingKeyManager;
import dev.cloudnative.learning.tlshotreload.x509.LoggingTrustManager;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManager;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManagerBuilder;
import org.apache.hc.client5.http.ssl.ClientTlsStrategyBuilder;
import org.apache.hc.client5.http.ssl.TlsSocketStrategy;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ssl.SslBundle;
import org.springframework.boot.ssl.SslBundles;
import org.springframework.boot.ssl.SslManagerBundle;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.web.client.RestClient;

import javax.net.ssl.*;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * Configuration class for creating a {@link RestClient} bean.
 * <p>
 * This configuration is responsible for setting up a RestClient that is specifically
 * configured for mutual TLS (mTLS) communication with a remote service. It uses an
 * SSL bundle named "remote" to obtain the necessary key and trust materials, wraps
 * them with logging interceptors for debugging, and builds an HTTP client with this
 * custom SSL context.
 */
@Configuration
public class RestClientConfig {

    @Value("${remote.url}")
    String remoteUrl;

    /**
     * Creates and configures a {@link RestClient} bean for communicating with a remote service over mTLS.
     * <p>
     * This method performs the following steps:
     * <ol>
     *   <li>Retrieves the {@link SslBundle} named "remote" which contains the client's key and trust stores.</li>
     *   <li>Wraps the default {@link KeyManager} and {@link TrustManager} from the bundle with custom logging versions
     *       ({@link LoggingKeyManager} and {@link LoggingTrustManager}) to provide visibility into the TLS handshake process.</li>
     *   <li>Initializes a new {@link SSLContext} with these wrapped managers.</li>
     *   <li>Builds an Apache {@link CloseableHttpClient} that uses a connection manager configured with the custom SSL context.</li>
     *   <li>Constructs a {@link RestClient} using this custom HTTP client and sets the base URL from the application properties.</li>
     * </ol>
     *
     * @param sslBundles The collection of all configured {@link SslBundle}s, injected by Spring.
     * @return A fully configured {@link RestClient} instance ready for mTLS communication.
     * @throws NoSuchAlgorithmException if the requested cryptographic algorithm is not available in the environment.
     * @throws KeyManagementException if an error occurs during the initialization of the SSLContext.
     */
    @Bean
    public RestClient restClient(SslBundles sslBundles) throws NoSuchAlgorithmException, KeyManagementException {

        // Get the SSL bundle by name
        SslBundle sslBundle = sslBundles.getBundle("remote");

        // Wrap original managers with logging versions
        SslManagerBundle managers = sslBundle.getManagers();
        KeyManager[] keyManagers = managers.getKeyManagers();
        TrustManager[] trustManagers = managers.getTrustManagers();

        KeyManager[] wrappedKeyManagers = wrapKeyManagers(keyManagers);
        TrustManager[] wrappedTrustManagers = wrapTrustManagers(trustManagers);

        SSLContext customContext = SSLContext.getInstance("TLS");
        customContext.init(
                wrappedKeyManagers,
                wrappedTrustManagers,
                new SecureRandom()
        );

        // Configure HTTP client with SSL context
        TlsSocketStrategy tlsSocketStrategy = (TlsSocketStrategy) ClientTlsStrategyBuilder.create()
                .setSslContext(customContext)
                .build();

        PoolingHttpClientConnectionManager connManager = PoolingHttpClientConnectionManagerBuilder.create()
                .setTlsSocketStrategy(tlsSocketStrategy)
                .build();

        CloseableHttpClient httpClient = HttpClients.custom()
                .setConnectionManager(connManager)
                .build();

        HttpComponentsClientHttpRequestFactory requestFactory =
                new HttpComponentsClientHttpRequestFactory(httpClient);

        return RestClient.builder()
                .requestFactory(requestFactory)
                .baseUrl(remoteUrl)
                .build();
    }

    private KeyManager[] wrapKeyManagers(KeyManager[] originals) {
        return Arrays.stream(originals)
                .map(km -> km instanceof X509KeyManager ?
                        new LoggingKeyManager((X509KeyManager) km) : km)
                .toArray(KeyManager[]::new);
    }

    private TrustManager[] wrapTrustManagers(TrustManager[] originals) {
        return Arrays.stream(originals)
                .map(tm -> tm instanceof X509TrustManager ?
                        new LoggingTrustManager((X509TrustManager) tm) : tm)
                .toArray(TrustManager[]::new);
    }
}
