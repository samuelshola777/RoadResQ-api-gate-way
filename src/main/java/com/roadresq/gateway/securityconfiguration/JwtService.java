package com.roadresq.gateway.securityconfiguration;

import com.roadresq.gateway.config.EnvValues;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.function.Function;

@Service
@Slf4j
public class JwtService {

    private final EnvValues envValues;

    private SecretKey key;

    public JwtService(EnvValues envValues) {
        this.envValues = envValues;
    }

    @PostConstruct
    public void init() {

        key = Keys.hmacShaKeyFor(
                Decoders.BASE64.decode(envValues.getJwtSecret())
        );

        log.info("JWT signing key initialized");
    }

    public Boolean isTokenValid(String token) {

        try {

            Claims claims = extractAllClaims(token);

            return claims.getExpiration() != null
                    && claims.getExpiration().after(new Date())
                    && claims.getSubject() != null
                    && !claims.getSubject().isBlank()
                    && "ACCESS_TOKEN".equals(
                    claims.get("type", String.class)
            );

        } catch (Exception e) {

            log.info("JWT validation failed");

            return false;
        }
    }

    public String extractUsername(String token) {

        return extractClaim(token, Claims::getSubject);
    }

    public Date extractExpiration(String token) {

        return extractClaim(token, Claims::getExpiration);
    }

    public <T> T extractClaim(
            String token,
            Function<Claims, T> claimsResolver
    ) {

        return claimsResolver.apply(extractAllClaims(token));
    }

    public Claims extractAllClaims(String token) {

        return Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }
}