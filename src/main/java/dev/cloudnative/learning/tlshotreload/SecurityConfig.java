package dev.cloudnative.learning.tlshotreload;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Configures the web security for the application using Spring Security.
 * <p>
 * This class defines the security filter chain that intercepts incoming HTTP requests
 * and applies security rules, such as requiring HTTPS for specific paths and enabling
 * X.509 client certificate authentication.
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {


    /**
     * Defines the primary {@link SecurityFilterChain} bean to configure HTTP security.
     * <p>
     * The configuration includes the following rules:
     * <ul>
     *   <li><b>Channel Security:</b> Enforces that all requests to paths under {@code /api/**}
     *       must be made over a secure channel (HTTPS).</li>
     *   <li><b>Authorization:</b>
     *       <ul>
     *           <li>Permits all requests to {@code /api/**} after the secure channel requirement is met.</li>
     *           <li>Allows anonymous access for all other requests (e.g., the root path "/").</li>
     *       </ul>
     *   </li>
     *   <li><b>X.509 Authentication:</b> Enables client certificate authentication and configures it
     *       to extract the user principal from the Common Name (CN) of the certificate's subject.</li>
     *   <li><b>CSRF:</b> Disables Cross-Site Request Forgery protection, which is a common practice
     *       for stateless APIs that are not vulnerable to this type of attack.</li>
     * </ul>
     *
     * @param http The {@link HttpSecurity} object to be configured.
     * @return The configured {@link SecurityFilterChain} instance.
     * @throws Exception if an error occurs during the configuration.
     */
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .requiresChannel(channel -> channel
                        .requestMatchers("/api/**").requiresSecure())
                .authorizeHttpRequests(authz -> authz
                        .requestMatchers("/api/**").permitAll()
                        .anyRequest().anonymous()
                )// Allow HTTP for all other paths
                .x509(x509 -> x509.subjectPrincipalRegex("CN=(.*?)(?:,|$)"))
                .csrf(AbstractHttpConfigurer::disable);

        return http.build();
    }
}