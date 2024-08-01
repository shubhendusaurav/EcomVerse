package com.EcomVerse.user_service.config;

import com.EcomVerse.user_service.utils.JwtAuthenticationFilter;
import com.EcomVerse.user_service.utils.JwtUtil;
import lombok.AllArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/**
 * SecurityConfig is a configuration class that sets up the security mechanisms
 * for the application, including authentication and authorization settings.
 */
@Configuration
@AllArgsConstructor
public class SecurityConfig {

    // Injecting UserDetailsService to fetch user details for authentication
    private final UserDetailsService userDetailsService;

    // Injecting JwtUtil to handle JWT operations like token generation and validation
    private final JwtUtil jwtUtil;

    /**
     * Defines a bean for password encoding using BCrypt hashing algorithm.
     *
     * @return an instance of BCryptPasswordEncoder.
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /**
     * Defines a bean for the AuthenticationManager, which is used to handle
     * authentication requests. It delegates the authentication process to the
     * configured authentication providers.
     *
     * @param authenticationConfiguration the configuration for authentication.
     * @return an AuthenticationManager instance.
     * @throws Exception if an error occurs during authentication manager setup.
     */
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    /**
     * Configures the security filter chain for HTTP requests. This includes setting
     * up CSRF protection, request authorization rules, and adding custom filters.
     *
     * @param http the HttpSecurity object to configure security settings.
     * @return the SecurityFilterChain configured for the application.
     * @throws Exception if an error occurs during the configuration.
     */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.csrf(csrf -> csrf.disable()) // Disable CSRF protection for the API
                .authorizeHttpRequests(authorizeRequests -> authorizeRequests
                        .requestMatchers("/authenticate").permitAll() // Allow unauthenticated access to /authenticate
                        .anyRequest().authenticated() // Require authentication for all other requests
                )
                // Add a custom JWT authentication filter before the standard authentication filter
                .addFilterBefore(new JwtAuthenticationFilter(jwtUtil, userDetailsService), UsernamePasswordAuthenticationFilter.class);

        // Build the security filter chain
        return http.build();
    }
}
