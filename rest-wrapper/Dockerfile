FROM adoptopenjdk/openjdk13:jre-13.0.2_8-alpine

LABEL Description="Dockerfile for the OLYMPUS REST client" Vendor="Alexandra Institute A/S" Version="0.0.1"

COPY /target/REST-client-wrapper-jar-with-dependencies.jar /app/
COPY /target/libs /app/libs/
COPY /src/test/resources/keystore.jks /app/config/keystore.jks

RUN apk add --no-cache openssl
RUN apk -U add ca-certificates

ENV DOCKERIZE_VERSION v0.6.1
RUN wget https://github.com/jwilder/dockerize/releases/download/$DOCKERIZE_VERSION/dockerize-linux-amd64-$DOCKERIZE_VERSION.tar.gz \
    && tar -C /usr/local/bin -xzvf dockerize-linux-amd64-$DOCKERIZE_VERSION.tar.gz \
    && rm dockerize-linux-amd64-$DOCKERIZE_VERSION.tar.gz

ENTRYPOINT ["java", "-jar", "app/REST-client-wrapper-jar-with-dependencies.jar", "pesto", "999", "http://host.docker.internal:9080", "http://host.docker.internal:9081", "http://host.docker.internal:9082"]