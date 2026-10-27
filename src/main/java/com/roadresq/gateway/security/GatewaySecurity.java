package com.roadresq.gateway.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.*;
import org.springframework.http.*;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.*;

import java.util.*;

import javax.crypto.spec.SecretKeySpec;

@Configuration
public class GatewaySecurity {
    public static final String[] PUBLIC_POSTS = {
        "/us-s/auth/public/register/customer",
        "/us-s/auth/public/register/provider",
        "/us-s/auth/public/login",
        "/us-s/auth/public/google",
        "/us-s/auth/public/refresh",
        "/us-s/auth/public/verify-email",
        "/us-s/auth/public/resend-verification",
        "/us-s/auth/public/forgot-password",
        "/us-s/auth/public/reset-password",
        "/us-s/auth/public/accept-invite",
        "/us-s/utilities/public/profile-picture"
    };

    @Bean
    ReactiveJwtDecoder jwtDecoder(
            @Value("${app.jwt-secret}") String secret,
            @Value("${app.issuer:road-resq-auth}") String issuer,
            @Value("${app.audience:road-resq}") String audience) {
        byte[] key = Base64.getDecoder().decode(secret);
        if (key.length < 32)
            throw new IllegalArgumentException(
                    "JWT secret requires at least 32 random bytes, base64 encoded");
        var decoder =
                NimbusReactiveJwtDecoder.withSecretKey(new SecretKeySpec(key, "HmacSHA256"))
                        .macAlgorithm(MacAlgorithm.HS256)
                        .build();
        decoder.setJwtValidator(
                new DelegatingOAuth2TokenValidator<>(
                        JwtValidators.createDefaultWithIssuer(issuer),
                        jwt -> {
                            boolean valid =
                                    jwt.getAudience().contains(audience)
                                            && "access".equals(jwt.getClaimAsString("token_use"))
                                            && jwt.getSubject() != null
                                            && jwt.getClaimAsString("sid") != null
                                            && jwt.getClaimAsString("role") != null
                                            && Set.of("CUSTOMER", "PROVIDER", "ADMIN")
                                                    .contains(jwt.getClaimAsString("role"));
                            return valid
                                    ? OAuth2TokenValidatorResult.success()
                                    : OAuth2TokenValidatorResult.failure(
                                            new OAuth2Error("invalid_token"));
                        }));
        return decoder;
    }

    @Bean
    SecurityWebFilterChain security(
            ServerHttpSecurity http, ReactiveJwtDecoder decoder, CorsConfigurationSource cors) {
        return http.csrf(c -> c.disable())
                .httpBasic(c -> c.disable())
                .formLogin(c -> c.disable())
                .cors(c -> c.configurationSource(cors))
                .authorizeExchange(
                        a ->
                                a.pathMatchers(HttpMethod.OPTIONS, "/**")
                                        .permitAll()
                                        .pathMatchers(
                                                HttpMethod.GET,
                                                "/health",
                                                "/us-s/utilities/public/profile-images/*")
                                        .permitAll()
                                        .pathMatchers(HttpMethod.POST, PUBLIC_POSTS)
                                        .permitAll()
                                        .pathMatchers("/us-s/**")
                                        .authenticated()
                                        .anyExchange()
                                        .denyAll())
                .oauth2ResourceServer(
                        o ->
                                o.jwt(j -> j.jwtDecoder(decoder))
                                        .authenticationEntryPoint(
                                                (e, err) ->
                                                        GatewayErrors.write(
                                                                e, 401, "Authentication required")))
                .exceptionHandling(
                        e ->
                                e.authenticationEntryPoint(
                                                (x, err) ->
                                                        GatewayErrors.write(
                                                                x, 401, "Authentication required"))
                                        .accessDeniedHandler(
                                                (x, err) ->
                                                        GatewayErrors.write(
                                                                x, 403, "Access denied")))
                .build();
    }

    @Bean
    CorsConfigurationSource cors(
            @Value("${app.allowed-origins:http://localhost:3000}") String origins) {
        CorsConfiguration c = new CorsConfiguration();
        c.setAllowedOrigins(Arrays.asList(origins.split(",")));
        c.setAllowedMethods(List.of("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"));
        c.setAllowedHeaders(List.of("Authorization", "X-Api-Key", "Content-Type"));
        c.setAllowCredentials(false);
        c.setMaxAge(3600L);
        var source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", c);
        return source;
    }
}
