package de.alexanderwolz.keycloak.docker.mapping

import org.keycloak.models.AuthenticatedClientSessionModel
import org.keycloak.models.KeycloakSession
import org.keycloak.models.ProtocolMapperModel
import org.keycloak.models.UserSessionModel
import org.keycloak.protocol.docker.mapper.DockerAuthV2AttributeMapper
import org.keycloak.protocol.docker.mapper.DockerAuthV2ProtocolMapper
import org.keycloak.representations.docker.DockerResponseToken

// reference: https://www.baeldung.com/keycloak-custom-protocol-mapper
// see also https://www.keycloak.org/docs-api/21.1.1/javadocs/org/keycloak/protocol/ProtocolMapper.html
// see also https://www.keycloak.org/docs-api/21.1.1/javadocs/org/keycloak/protocol/docker/mapper/DockerAuthV2ProtocolMapper.html
// see also https://docs.docker.com/registry/spec/auth/token/

class KeycloakGroupsToDockerRoleMapper : DockerAuthV2ProtocolMapper(), DockerAuthV2AttributeMapper {

    override fun getId(): String {
        return "keycloak_docker_group_mapper";
    }

    override fun getDisplayType(): String {
        //TODO update this text
        return "Docker Registry v2 scope mapping by user roles and group";
    }

    override fun getHelpText(): String {
        //TODO update this text
        return "Maps Docker registry v2 scopes by user roles and groups";
    }

    override fun appliesTo(responseToken: DockerResponseToken?): Boolean {
        //TODO: do we have to look at the token here?
        return true
    }

    override fun transformDockerResponseToken(
        responseToken: DockerResponseToken,
        mappingModel: ProtocolMapperModel?,
        session: KeycloakSession?,
        userSession: UserSessionModel?,
        clientSession: AuthenticatedClientSessionModel?
    ): DockerResponseToken {
        //TODO implement me
        return responseToken
    }
}