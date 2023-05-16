ARG KEYCLOAK_VERSION="21.1.1"
ARG MAPPER_VERSION="1.1.0"

# stage 1: keycloak build
FROM keycloak/keycloak:${KEYCLOAK_VERSION} as builder
LABEL maintainer="mail@alexanderwolz.de"
ARG MAPPER_VERSION
ENV KC_FEATURES=docker,token-exchange
COPY keycloak-docker-group-role-mapper-${MAPPER_VERSION}.jar /opt/keycloak/providers/
RUN /opt/keycloak/bin/kc.sh build

## stage 2: runtime
FROM keycloak/keycloak:${KEYCLOAK_VERSION} as runtime
LABEL maintainer="mail@alexanderwolz.de"
COPY --from=builder /opt/keycloak/lib/quarkus/ /opt/keycloak/lib/quarkus/
COPY --from=builder /opt/keycloak/providers/ /opt/keycloak/providers/
WORKDIR /opt/keycloak
ENV KEYCLOAK_ADMIN=admin
ENV KEYCLOAK_ADMIN_PASSWORD=admin
ENV KC_DB=mariadb
ENV KC_DB_URL=jdbc:mariadb://database:3306/database
ENV KC_DB_USERNAME=keycloak
ENV KC_DB_PASSWORD=keycloak
ENV KC_HOSTNAME=example.com
ENV KC_HOSTNAME_STRICT=false
ENV KC_PROXY=edge
ENV KC_HTTP_ENABLED=true
ENTRYPOINT ["/opt/keycloak/bin/kc.sh"]
CMD ["start", "--optimized"]
