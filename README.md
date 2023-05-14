# Docker v2 - Groups and Role Mapper for Keycloak 21.x
This repository provides a MappingProvider for Keycloak's Docker Registry V2 protocol.

It allows access for all users with client role ```admin``` or who belong to a realm group starting with prefix ```registry-```.

## Build
1. Create jar resource using ```./gradlew clean build```
2. Copy  ```/build/libs/keycloak-docker-group-role-mapper-1.0.0.jar``` into Keycloak´s ```/opt/keycloak/providers/``` folder
3. Build keycloak instance using ```/opt/keycloak/bin/kc.sh build```

See also Keycloak [Dockerfile](https://github.com/alexanderwolz/keycloak-docker-group-role-mapper/blob/main/examples/keycloak-with-mapper/Dockerfile) for reference in [examples](https://github.com/alexanderwolz/keycloak-docker-group-role-mapper/tree/main/examples) section.

- - -
Made with ❤️ in Bavaria
<br>
© 2023, <a href="https://www.alexanderwolz.de"> Alexander Wolz
