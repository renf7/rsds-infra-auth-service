FROM eclipse-temurin:27-jdk-alpine AS build
WORKDIR /app
COPY .mvn .mvn
COPY mvnw pom.xml ./
RUN sh mvnw -B -DskipTests dependency:go-offline
COPY src src
RUN sh mvnw -B -DskipTests package
FROM eclipse-temurin:27-jre-alpine
RUN apk upgrade --no-cache
WORKDIR /app
COPY --from=build --chown=10001:10001 /app/target/*.jar /app/app.jar
USER 10001:10001
EXPOSE 8080
ENTRYPOINT ["java","-XX:MaxRAMPercentage=70","-Djava.io.tmpdir=/tmp","-jar","/app/app.jar"]

