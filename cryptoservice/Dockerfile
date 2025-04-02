FROM maven:3.9.6-eclipse-temurin-21 AS build
WORKDIR /app
COPY . .
RUN mvn clean package -DskipTests

FROM openjdk:21-jdk-slim
WORKDIR /app
COPY --from=build /app/target/*.jar cryptoservice.jar

# TLS und Keystore Verzeichnis
VOLUME /app/tls
VOLUME /app/keystore

EXPOSE 8443
ENTRYPOINT ["java", "-jar", "cryptoservice.jar"]
