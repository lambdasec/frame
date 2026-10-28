FROM maven:3-eclipse-temurin-17 AS build
COPY . /src
RUN cd /src && mvn -q package

FROM eclipse-temurin:17
COPY --from=build /src/target/orders-1.0.0.jar /app.jar
ENV LOG4J_FORMAT_MSG_NO_LOOKUPS=true
CMD ["java", "-jar", "/app.jar"]
