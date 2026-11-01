package com.roadresq.gateway.securityconfiguration;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.roadresq.gateway.config.EnvValues;
import com.roadresq.gateway.utils.ServicePlatformType;
import io.jsonwebtoken.Claims;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.List;

@Component
@Slf4j
@AllArgsConstructor
public class LoggingGlobalFilter implements GlobalFilter, Ordered {

    private final RouteValidator routerValidator;

    private final JwtService jwtService;

    private final EnvValues envValues;

    private final ObjectMapper objectMapper;

    @Override
    public int getOrder() {

        return -1;
    }

    @Override
    public Mono<Void> filter(
            ServerWebExchange exchange,
            GatewayFilterChain chain
    ) {

        ServerHttpRequest request = exchange.getRequest();

        String path = request.getPath().value();

        log.info(
                "Gateway request received: method={}, path={}",
                request.getMethod(),
                path
        );

        String apiKey = getSingleHeader(request, "X-Api-Key");

        if (!isApiKeyValid(apiKey)) {

            return onError(
                    exchange,
                    HttpStatus.UNAUTHORIZED,
                    "Invalid request source."
            );
        }

        String platformValue = getSingleHeader(
                request,
                "X-Service-Type"
        );

        ServicePlatformType platform;

        try {

            platform = ServicePlatformType.valueOf(
                    platformValue == null ? "" : platformValue
            );

        } catch (IllegalArgumentException e) {

            return onError(
                    exchange,
                    HttpStatus.BAD_REQUEST,
                    "A valid X-Service-Type header is required."
            );
        }

        if (path.startsWith("/road-resq/")
                && platform != ServicePlatformType.ROAD_RESQ) {

            return onError(
                    exchange,
                    HttpStatus.FORBIDDEN,
                    "Platform does not match the requested service."
            );
        }

        log.info(
                "Request source validated: platform={}",
                platform
        );

        if (routerValidator.isSecured.test(request)) {

            String authorization = getSingleHeader(
                    request,
                    "Authorization"
            );

            if (authorization == null
                    || !authorization.startsWith("Bearer ")) {

                return onError(
                        exchange,
                        HttpStatus.UNAUTHORIZED,
                        "A Bearer access token is required."
                );
            }

            String token = authorization.substring(7).trim();

            if (token.isEmpty()
                    || !jwtService.isTokenValid(token)) {

                return onError(
                        exchange,
                        HttpStatus.UNAUTHORIZED,
                        "Your session is invalid or expired. Please sign in again."
                );
            }

            try {

                Claims claims = jwtService.extractAllClaims(token);

                String tokenPlatform = claims.get(
                        "servicePlatformType",
                        String.class
                );

                if (!platform.name().equals(tokenPlatform)) {

                    return onError(
                            exchange,
                            HttpStatus.FORBIDDEN,
                            "Your token does not permit access to this platform."
                    );
                }

            } catch (Exception e) {

                return onError(
                        exchange,
                        HttpStatus.UNAUTHORIZED,
                        "Invalid access token."
                );
            }

            log.info(
                    "Protected request validated: platform={}",
                    platform
            );

        } else {

            log.info(
                    "Public request validated: platform={}",
                    platform
            );
        }

        // Remove client-supplied identity headers on every forwarded request.
        // Backends must obtain the user's identity from the validated token.
        ServerHttpRequest updatedRequest = request.mutate()
                .headers(headers -> {

                    headers.remove("UserId");
                    headers.remove("UserType");
                    headers.remove("UserRole");
                    headers.remove("User-Type");
                    headers.remove("Admin-Level");
                    headers.remove("Permissions");
                    headers.remove("Email");
                    headers.remove("userSubscriptionId");
                    headers.remove("userSubscriptionName");
                    headers.remove("X-Client-IP");
                    headers.remove("Sender");

                    headers.set(
                            "X-Service-Type",
                            platform.name()
                    );

                    headers.set(
                            "X-Api-Key",
                            envValues.getApiKey()
                    );
                })
                .build();

        return chain.filter(
                exchange.mutate()
                        .request(updatedRequest)
                        .build()
        );
    }

    private String getSingleHeader(
            ServerHttpRequest request,
            String name
    ) {

        List<String> values = request.getHeaders().get(name);

        if (values == null
                || values.size() != 1
                || values.get(0).isBlank()) {

            return null;
        }

        return values.get(0);
    }

    private boolean isApiKeyValid(String provided) {

        String expected = envValues.getApiKey();

        if (provided == null
                || expected == null
                || expected.isBlank()) {

            return false;
        }

        return MessageDigest.isEqual(
                expected.getBytes(StandardCharsets.UTF_8),
                provided.getBytes(StandardCharsets.UTF_8)
        );
    }

    private Mono<Void> onError(
            ServerWebExchange exchange,
            HttpStatus status,
            String message
    ) {

        log.info(
                "Gateway request rejected: status={}, reason={}",
                status.value(),
                message
        );

        exchange.getResponse().setStatusCode(status);

        exchange.getResponse()
                .getHeaders()
                .setContentType(MediaType.APPLICATION_JSON);

        try {

            ApiResponse response = new ApiResponse(
                    false,
                    message,
                    null
            );

            byte[] bytes = objectMapper.writeValueAsBytes(response);

            return exchange.getResponse().writeWith(
                    Mono.just(
                            exchange.getResponse()
                                    .bufferFactory()
                                    .wrap(bytes)
                    )
            );

        } catch (Exception e) {

            log.info("Gateway error response serialization failed");

            return exchange.getResponse().setComplete();
        }
    }
}