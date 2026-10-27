package com.roadresq.gateway.filter;

import com.roadresq.gateway.security.GatewayErrors;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.*;
import org.springframework.core.Ordered;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;

import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

@Component
public class TrustedHeadersFilter implements GlobalFilter, Ordered {
    private final String internalKey, apiKey;
    private final int limit;

    private record Bucket(long minute, int count) {}

    private final ConcurrentHashMap<String, Bucket> buckets = new ConcurrentHashMap<>();

    public TrustedHeadersFilter(
            @Value("${app.internal-key}") String internalKey,
            @Value("${app.api-key}") String apiKey,
            @Value("${app.rate-limit:30}") int limit) {
        if (internalKey.length() < 32 || apiKey.length() < 32)
            throw new IllegalArgumentException(
                    "Service and client keys require at least 32 characters");
        this.internalKey = internalKey;
        this.apiKey = apiKey;
        this.limit = limit;
    }

    public int getOrder() {
        return -100;
    }

    private boolean allow(String ip) {
        long minute = System.currentTimeMillis() / 60000;
        if (buckets.size() > 10000) {
            buckets.entrySet().removeIf(e -> e.getValue().minute() < minute);
            if (buckets.size() > 10000 && !buckets.containsKey(ip)) return false;
        }
        Bucket b =
                buckets.compute(
                        ip,
                        (k, old) ->
                                old == null || old.minute() != minute
                                        ? new Bucket(minute, 1)
                                        : new Bucket(minute, Math.min(old.count() + 1, limit + 1)));
        return b.count() <= limit;
    }

    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        String path = exchange.getRequest().getPath().value();
        boolean publicImageRead =
                exchange.getRequest().getMethod() == org.springframework.http.HttpMethod.GET
                        && path.matches(
                                "/us-s/utilities/public/profile-images/[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}");
        String sent = exchange.getRequest().getHeaders().getFirst("X-Api-Key");
        if (!publicImageRead
                && (sent == null
                        || !MessageDigest.isEqual(
                                apiKey.getBytes(StandardCharsets.UTF_8),
                                sent.getBytes(StandardCharsets.UTF_8))))
            return GatewayErrors.write(exchange, 401, "Invalid client API key");
        String ip =
                exchange.getRequest().getRemoteAddress() == null
                        ? "unknown"
                        : exchange.getRequest().getRemoteAddress().getAddress().getHostAddress();
        if (exchange.getRequest().getMethod() == org.springframework.http.HttpMethod.POST
                && (path.contains("/auth/public/") || path.endsWith("/profile-picture"))
                && !allow(ip))
            return GatewayErrors.write(exchange, 429, "Too many requests. Try again shortly");
        return exchange.getPrincipal()
                .cast(java.security.Principal.class)
                .map(Optional::of)
                .defaultIfEmpty(Optional.empty())
                .flatMap(
                        principal -> {
                            var request =
                                    exchange.getRequest()
                                            .mutate()
                                            .headers(
                                                    h -> {
                                                        for (String name :
                                                                List.of(
                                                                        "X-Internal-Key",
                                                                        "X-Api-Key",
                                                                        "UserId",
                                                                        "UserRole",
                                                                        "ClientId",
                                                                        "Email",
                                                                        "Sender",
                                                                        "CustomerId",
                                                                        "ProviderId",
                                                                        "AdminId",
                                                                        "ProfileId",
                                                                        "X-User-Id",
                                                                        "X-User-Role",
                                                                        "X-Client-IP",
                                                                        "X-Request-Id",
                                                                        "X-Forwarded-For",
                                                                        "X-Forwarded-Host",
                                                                        "X-Forwarded-Proto",
                                                                        "Forwarded"))
                                                            h.remove(name);
                                                        h.set("X-Internal-Key", internalKey);
                                                        h.set("Sender", "road-resq-gateway");
                                                        h.set("X-Client-IP", ip);
                                                        h.set(
                                                                "X-Request-Id",
                                                                UUID.randomUUID().toString());
                                                        principal
                                                                .filter(
                                                                        p ->
                                                                                p
                                                                                        instanceof
                                                                                        JwtAuthenticationToken)
                                                                .map(
                                                                        p ->
                                                                                ((JwtAuthenticationToken)
                                                                                                p)
                                                                                        .getToken())
                                                                .ifPresent(
                                                                        jwt -> {
                                                                            h.set(
                                                                                    "UserId",
                                                                                    jwt
                                                                                            .getSubject());
                                                                            h.set(
                                                                                    "UserRole",
                                                                                    jwt
                                                                                            .getClaimAsString(
                                                                                                    "role"));
                                                                        });
                                                    })
                                            .build();
                            return chain.filter(exchange.mutate().request(request).build());
                        });
    }
}
