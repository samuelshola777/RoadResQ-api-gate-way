package com.roadresq.gateway.securityconfiguration;

import org.springframework.http.HttpMethod;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.function.Predicate;
import java.util.regex.Pattern;
import java.util.stream.Stream;

@Component
public class RouteValidator {

    // Gateway URLs before /auth is rewritten to /api/v1.
    public static final List<Pattern> AUTH_OPEN_ENDPOINTS = List.of(
            // Customer authentication
            Pattern.compile("^/auth/customer/public/register$"),
            Pattern.compile("^/auth/customer/public/login$"),
            Pattern.compile("^/auth/customer/public/verify-otp$"),
            Pattern.compile("^/auth/customer/public/resend-otp$"),
            Pattern.compile("^/auth/customer/public/forgot-password$"),
            Pattern.compile("^/auth/customer/public/reset-password$"),

            // Vendor authentication
            Pattern.compile("^/auth/vendor/public/register$"),
            Pattern.compile("^/auth/vendor/public/login$"),
            Pattern.compile("^/auth/vendor/public/verify-otp$"),
            Pattern.compile("^/auth/vendor/public/resend-otp$"),
            Pattern.compile("^/auth/vendor/public/forgot-password$"),
            Pattern.compile("^/auth/vendor/public/reset-password$"),

            // Admin authentication
            Pattern.compile("^/auth/admin/public/login$"),
            Pattern.compile("^/auth/admin/public/forgot-password$"),
            Pattern.compile("^/auth/admin/public/reset-password$"),

            // File upload
            Pattern.compile("^/auth/utilities/public/file/upload$")
    );

    public static final List<Pattern> SYSTEM_OPEN_ENDPOINTS = List.of(
            Pattern.compile("^/health$"),
            Pattern.compile("^/auth/system/public/health$")
    );

    public static final List<Pattern> ALL_OPEN_ENDPOINTS =
            Stream.concat(
                    AUTH_OPEN_ENDPOINTS.stream(),
                    SYSTEM_OPEN_ENDPOINTS.stream()
            ).toList();

    public final Predicate<ServerHttpRequest> isPublic = request -> {
        String path = request.getPath().value();
        HttpMethod method = request.getMethod();

        if (HttpMethod.POST.equals(method)) {
            return matches(AUTH_OPEN_ENDPOINTS, path);
        }

        if (HttpMethod.GET.equals(method)) {
            return matches(SYSTEM_OPEN_ENDPOINTS, path);
        }

        return false;
    };

    public final Predicate<ServerHttpRequest> isSecured =
            request -> !isPublic.test(request);

    private static boolean matches(
            List<Pattern> patterns,
            String path
    ) {
        return patterns.stream()
                .anyMatch(pattern -> pattern.matcher(path).matches());
    }
}