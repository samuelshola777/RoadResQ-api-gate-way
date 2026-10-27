package com.roadresq.gateway.security;

import org.springframework.http.*;
import org.springframework.web.server.ServerWebExchange;

import reactor.core.publisher.Mono;

public final class GatewayErrors {
    private GatewayErrors() {}

    public static Mono<Void> write(ServerWebExchange e, int status, String message) {
        e.getResponse().setStatusCode(HttpStatusCode.valueOf(status));
        e.getResponse().getHeaders().setContentType(MediaType.APPLICATION_JSON);
        byte[] bytes =
                ("{\"success\":false,\"message\":\"" + message + "\",\"data\":null}")
                        .getBytes(java.nio.charset.StandardCharsets.UTF_8);
        return e.getResponse().writeWith(Mono.just(e.getResponse().bufferFactory().wrap(bytes)));
    }
}
