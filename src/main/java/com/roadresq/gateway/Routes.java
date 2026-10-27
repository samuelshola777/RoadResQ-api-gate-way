package com.roadresq.gateway;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.route.*;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.context.annotation.*;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@Configuration
public class Routes {
    @Bean
    RouteLocator authRoutes(
            RouteLocatorBuilder b,
            @Value("${app.auth-service-url:http://localhost:8081}") String authUrl) {
        return b.routes()
                .route(
                        "auth-service",
                        r -> r.path("/us-s/**").filters(f -> f.prefixPath("/api/v1")).uri(authUrl))
                .build();
    }

    @RestController
    static class Health {
        @GetMapping("/health")
        public Map<String, Object> health() {
            return Map.of(
                    "success",
                    true,
                    "message",
                    "Gateway is running",
                    "data",
                    Map.of("status", "UP"));
        }
    }
}
