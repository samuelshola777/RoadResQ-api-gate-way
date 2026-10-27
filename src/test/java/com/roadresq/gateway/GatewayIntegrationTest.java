package com.roadresq.gateway;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.jwk.source.ImmutableSecret;
import com.sun.net.httpserver.HttpServer;

import org.junit.jupiter.api.*;
import org.springframework.boot.test.autoconfigure.web.reactive.AutoConfigureWebTestClient;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.test.context.*;
import org.springframework.test.web.reactive.server.WebTestClient;

import java.net.InetSocketAddress;
import java.time.Instant;
import java.util.*;

import javax.crypto.spec.SecretKeySpec;

@SpringBootTest(
        webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = {
            "app.jwt-secret=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            "app.internal-key=test-internal-key-with-at-least-32-characters",
            "app.api-key=test-client-key-with-at-least-32-characters",
            "app.rate-limit=1000"
        })
@AutoConfigureWebTestClient
class GatewayIntegrationTest {
    static HttpServer upstream;

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry r) throws Exception {
        upstream = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        upstream.createContext(
                "/",
                exchange -> {
                    var values = new LinkedHashMap<String, Object>();
                    values.put("path", exchange.getRequestURI().getPath());
                    for (String name :
                            List.of("X-Internal-Key", "UserId", "UserRole", "Sender", "X-Api-Key"))
                        values.put(name, exchange.getRequestHeaders().getFirst(name));
                    byte[] response = new ObjectMapper().writeValueAsBytes(values);
                    exchange.getResponseHeaders().set("Content-Type", "application/json");
                    exchange.sendResponseHeaders(200, response.length);
                    exchange.getResponseBody().write(response);
                    exchange.close();
                });
        upstream.start();
        r.add("app.auth-service-url", () -> "http://127.0.0.1:" + upstream.getAddress().getPort());
    }

    @AfterAll
    static void stop() {
        upstream.stop(0);
    }

    @org.springframework.boot.test.web.server.LocalServerPort int port;
    WebTestClient http;

    @BeforeEach
    void client() {
        http = WebTestClient.bindToServer().baseUrl("http://localhost:" + port).build();
    }

    String jwt(String audience, String type, Instant expiry) {
        return jwt(audience, type, expiry, "CUSTOMER");
    }

    String jwt(String audience, String type, Instant expiry, String role) {
        var encoder =
                new NimbusJwtEncoder(
                        new ImmutableSecret<>(new SecretKeySpec(new byte[32], "HmacSHA256")));
        var claims =
                JwtClaimsSet.builder()
                        .issuer("road-resq-auth")
                        .audience(List.of(audience))
                        .subject("real-user")
                        .issuedAt(Instant.now().minusSeconds(600))
                        .expiresAt(expiry)
                        .claim("sid", "real-session")
                        .claims(
                                c -> {
                                    if (role != null) c.put("role", role);
                                })
                        .claim("token_use", type)
                        .claim("ver", 0)
                        .build();
        return encoder.encode(
                        JwtEncoderParameters.from(
                                JwsHeader.with(MacAlgorithm.HS256).build(), claims))
                .getTokenValue();
    }

    @Test
    void publicRoutePrefixesPathAndReplacesSpoofedHeaders() {
        http.post()
                .uri("/us-s/auth/public/login")
                .header("X-Api-Key", "test-client-key-with-at-least-32-characters")
                .header("X-Internal-Key", "fake")
                .header("UserId", "fake-admin")
                .header("UserRole", "ADMIN")
                .header("Sender", "gateway")
                .exchange()
                .expectStatus()
                .isOk()
                .expectBody()
                .jsonPath("$.path")
                .isEqualTo("/api/v1/us-s/auth/public/login")
                .jsonPath("$.X-Internal-Key")
                .isEqualTo("test-internal-key-with-at-least-32-characters")
                .jsonPath("$.UserId")
                .doesNotExist()
                .jsonPath("$.Sender")
                .isEqualTo("road-resq-gateway")
                .jsonPath("$.X-Api-Key")
                .doesNotExist();
    }

    @Test
    void privateRouteRequiresBearer() {
        http.get()
                .uri("/us-s/account/me")
                .header("X-Api-Key", "test-client-key-with-at-least-32-characters")
                .exchange()
                .expectStatus()
                .isUnauthorized();
    }

    @Test
    void validJwtForwardsOnlyValidatedIdentity() {
        http.get()
                .uri("/us-s/account/me")
                .header("X-Api-Key", "test-client-key-with-at-least-32-characters")
                .header("UserId", "fake-admin")
                .header("UserRole", "ADMIN")
                .headers(
                        h ->
                                h.setBearerAuth(
                                        jwt("road-resq", "access", Instant.now().plusSeconds(900))))
                .exchange()
                .expectStatus()
                .isOk()
                .expectBody()
                .jsonPath("$.UserId")
                .isEqualTo("real-user")
                .jsonPath("$.UserRole")
                .isEqualTo("CUSTOMER");
    }

    @Test
    void wrongAudienceRefreshAndExpiredJwtAreRejected() {
        for (String token :
                List.of(
                        jwt("other", "access", Instant.now().plusSeconds(900)),
                        jwt("road-resq", "refresh", Instant.now().plusSeconds(900)),
                        jwt("road-resq", "access", Instant.now().minusSeconds(120)),
                        "opaque-refresh-token"))
            http.get()
                    .uri("/us-s/account/me")
                    .header("X-Api-Key", "test-client-key-with-at-least-32-characters")
                    .headers(h -> h.setBearerAuth(token))
                    .exchange()
                    .expectStatus()
                    .isUnauthorized();
    }

    @Test
    void publicRouteRequiresClientKey() {
        http.post().uri("/us-s/auth/public/login").exchange().expectStatus().isUnauthorized();
    }

    @Test
    void healthDoesNotRequireKeys() {
        http.get().uri("/health").exchange().expectStatus().isOk();
    }

    @Test
    void corsAllowsConfiguredOriginOnly() {
        http.options()
                .uri("/us-s/auth/public/login")
                .header("Origin", "http://localhost:3000")
                .header("Access-Control-Request-Method", "POST")
                .header("Access-Control-Request-Headers", "authorization,x-api-key,content-type")
                .exchange()
                .expectStatus()
                .isOk()
                .expectHeader()
                .valueEquals("Access-Control-Allow-Origin", "http://localhost:3000");
    }

    @Test
    void missingRoleIsUnauthorizedRatherThanServerError() {
        http.get()
                .uri("/us-s/account/me")
                .header("X-Api-Key", "test-client-key-with-at-least-32-characters")
                .headers(
                        h ->
                                h.setBearerAuth(
                                        jwt(
                                                "road-resq",
                                                "access",
                                                Instant.now().plusSeconds(900),
                                                null)))
                .exchange()
                .expectStatus()
                .isUnauthorized();
    }

    @Test
    void publicImageUrlCanBeReadWithoutClientKey() {
        http.get()
                .uri("/us-s/utilities/public/profile-images/00000000-0000-0000-0000-000000000000")
                .exchange()
                .expectStatus()
                .isOk()
                .expectBody()
                .jsonPath("$.X-Internal-Key")
                .isEqualTo("test-internal-key-with-at-least-32-characters");
    }
}
