package de.alexanderwolz.keycloak.docker.mapping

import org.jboss.logging.Logger
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

class KeycloakGroupsAndRolesToDockerScopeMapper : DockerAuthV2ProtocolMapper(), DockerAuthV2AttributeMapper {

    companion object {
        private const val PROVIDER_ID = "docker-v2-allow-by-groups-and-roles-mapper"
        private const val DISPLAY_TYPE = "Allow by Groups and Roles"
        private const val HELP_TEXT = "Maps Docker v2 scopes by user roles and groups"

        private const val ROLE_ADMIN = "admin"
    }

    private val logger = Logger.getLogger(javaClass.simpleName)

    override fun getId(): String {
        return PROVIDER_ID
    }

    override fun getDisplayType(): String {
        return DISPLAY_TYPE
    }

    override fun getHelpText(): String {
        return HELP_TEXT
    }

    override fun appliesTo(responseToken: DockerResponseToken?): Boolean {
        return true
    }

    //TODO implement me
    override fun transformDockerResponseToken(
        responseToken: DockerResponseToken,
        mappingModel: ProtocolMapperModel,
        session: KeycloakSession,
        userSession: UserSessionModel,
        clientSession: AuthenticatedClientSessionModel
    ): DockerResponseToken {

        logger.debug("Access Items: ${responseToken.accessItems.size}")

        val clientRoleNames = userSession.user.getClientRoleMappingsStream(clientSession.client)
            .map { it.name.lowercase() }.toList()

        if (clientRoleNames.contains(ROLE_ADMIN)) {
            if (logger.isDebugEnabled) {
                logger.debug("Granting all access for user '${userSession.user.username}' because user is admin")
            }
            return responseToken //admins can access everything
        }

        val groupNames = userSession.user.groupsStream.map { it.name.lowercase() }.toList()
        if (logger.isDebugEnabled) {
            logger.debug("User: ${userSession.user.username}")
            logger.debug("Groups: ${groupNames.joinToString()}")
            logger.debug("Client Roles: ${clientRoleNames.joinToString()}")
        }

        //TODO implement role and group mapping

        return responseToken
    }
}