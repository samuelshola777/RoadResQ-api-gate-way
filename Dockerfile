FROM maven:3.9-eclipse-temurin-21 AS build
WORKDIR /build
COPY pom.xml .
COPY src ./src
RUN mvn -B -DskipTests package

FROM eclipse-temurin:21-jre
WORKDIR /app
RUN groupadd --system roadresq \
    && useradd --system --gid roadresq roadresq \
    && mkdir -p /app/uploads \
    && chown -R roadresq:roadresq /app

COPY --from=build /build/target/*.jar /app/service.jar
USER roadresq
EXPOSE 8070
ENTRYPOINT ["java", "-jar", "/app/service.jar"]