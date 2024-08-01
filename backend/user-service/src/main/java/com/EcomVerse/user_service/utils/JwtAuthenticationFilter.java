package com.EcomVerse.user_service.utils;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * JwtAuthenticationFilter is a custom filter that extends OncePerRequestFilter.
 * It intercepts HTTP requests to check for a JWT token in the Authorization header,
 * validates the token, and sets the authentication context if the token is valid.
 */
@Component
@AllArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtUtil jwtUtil; // Utility class for handling JWT operations
    private final UserDetailsService userDetailsService; // Service to load user-specific data

    /**
     * Filters each request to check for a JWT token in the Authorization header.
     * If a valid token is found, it sets the authentication context.
     *
     * @param request  the HTTP request
     * @param response the HTTP response
     * @param chain    the filter chain
     * @throws ServletException if a servlet-specific error occurs
     * @throws IOException      if an I/O error occurs
     */
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {

        // Get the Authorization header from the request
        final String authorizationHeader = request.getHeader("Authorization");

        String username = null;
        String jwt = null;

        // Check if the Authorization header contains a Bearer token
        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
            // Extract the JWT token from the header
            jwt = authorizationHeader.substring(7);
            // Extract the username from the token
            username = jwtUtil.extractUsername(jwt);
        }

        // If a username is extracted and no authentication context is set
        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            // Load user details from the database or another source
            UserDetails userDetails = this.userDetailsService.loadUserByUsername(username);

            // Validate the token using the username
            if (jwtUtil.validateToken(jwt, userDetails.getUsername())) {
                // Create a UsernamePasswordAuthenticationToken with the user details and authorities
                UsernamePasswordAuthenticationToken authenticationToken =
                        new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());

                // Set additional details, such as the remote IP address
                authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                // Set the authentication in the security context
                SecurityContextHolder.getContext().setAuthentication(authenticationToken);
            }
        }

        // Continue the filter chain
        chain.doFilter(request, response);
    }
}
