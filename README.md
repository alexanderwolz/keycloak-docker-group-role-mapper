# Docker v2 - Groups and Role Mapper for Keycloak 21.x
This repository provides a MappingProvider for Keycloak's Docker Registry V2 protocol. It manages access for users with client role ```admin``` or ```editor``` or who belong to a realm group starting with prefix ```registry-```.

## Build
1. Create jar resource using ```./gradlew clean build```
2. Copy  ```/build/libs/keycloak-docker-group-role-mapper-1.0.0.jar``` into Keycloak´s ```/opt/keycloak/providers/``` folder
3. Build keycloak instance using ```/opt/keycloak/bin/kc.sh build```

See also Keycloak [Dockerfile](https://github.com/alexanderwolz/keycloak-docker-group-role-mapper/blob/main/examples/keycloak-with-mapper/Dockerfile) for reference in [examples](https://github.com/alexanderwolz/keycloak-docker-group-role-mapper/tree/main/examples) section.

## Basic Requirements
You need to create ```admin``` and ```editor``` roles in the client role settings of keycloak. You can group users to the same repository namespace by assigning them to a group starting with ```registry-```.

For example: users that shall have access to *myregistry.com/mycompany/alpine/1.2.3-custom* should be assigned to group ```registry-mycompany```. All users will have read-only (pull) access by default.

By assigning the role ```editor``` they are also allowed to push and delete images in their namespaces (they can belong to several registry groups though).

Assigning the client role ```admin``` will allow access to any resource in the registry and give full access.

Don't forget to remove the "*Allow All*"-Mapper in the dedicated scope of your registry client configuration and set this Mapper by adding "*Allow by Groups and Roles*"-Mapper.

## Configuration
By setting an environment variable ```REGISTRY_CATALOG_AUDIENCE``` to either ```user``` or ```editor```, access can be granted to the catalog scope on the registry type (e.g. registry:catalog:*).
This may be of interest while using UI frontends such as [registry-ui](https://github.com/Joxit/docker-registry-ui).

- - -
Made with ❤️ in Bavaria
<br>
© 2023, <a href="https://www.alexanderwolz.de"> Alexander Wolz
