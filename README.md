# Road ResQ API Gateway

Independent Java 17 / Spring Boot 3.5.16 / Spring Cloud 2025.0.3 reactive Maven project. Default port 8080.

Run `./mvnw verify`; tests use a real local HTTP upstream and do not require Mongo or Docker. Run `./mvnw spring-boot:run` after exporting configuration.

Required environment: `JWT_SECRET` (same as Auth), `INTERNAL_SERVICE_KEY` (same as Auth), and `GATEWAY_API_KEY` (32+ characters). Set `AUTH_SERVICE_URL`, `ALLOWED_ORIGINS`, `JWT_ISSUER`, `JWT_AUDIENCE` and `PUBLIC_RATE_LIMIT` as needed.

Routes `/us-s/**` to Auth with `/api/v1` prefixed. Clients supply `X-Api-Key`, and a Bearer access token on protected endpoints. Spoofed identity/internal headers are removed before validated headers are inserted. `GET /health` needs no key and reports gateway liveness only.

Auth independently checks accounts, sessions and permissions. The gateway does not own a database or account records. The root README and `docs/api.md` contain the shared contract.
