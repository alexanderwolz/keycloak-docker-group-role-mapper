package de.alexanderwolz.keycloak.docker.mapping

import org.jboss.logging.Logger
import org.keycloak.models.AuthenticatedClientSessionModel
import org.keycloak.models.KeycloakSession
import org.keycloak.models.ProtocolMapperModel
import org.keycloak.models.UserSessionModel
import org.keycloak.protocol.docker.DockerAuthV2Protocol
import org.keycloak.protocol.docker.mapper.DockerAuthV2AttributeMapper
import org.keycloak.protocol.docker.mapper.DockerAuthV2ProtocolMapper
import org.keycloak.representations.docker.DockerAccess
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

        //see also https://docs.docker.com/registry/spec/auth/scope/
        private const val ACCESS_TYPE_REGISTRY = "registry"
        private const val ACCESS_TYPE_REPOSITORY = "repository"
        private const val ACCESS_TYPE_REPOSITORY_PLUGIN = "repository(plugin)"

        private const val ROLE_ADMIN = "admin"
        private const val GROUP_PREFIX = "registry-"
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

    override fun transformDockerResponseToken(
        responseToken: DockerResponseToken,
        mappingModel: ProtocolMapperModel,
        session: KeycloakSession,
        userSession: UserSessionModel,
        clientSession: AuthenticatedClientSessionModel
    ): DockerResponseToken {

        val scope = clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM)
            ?: return responseToken //no scope, no worries

        val accessItem = parseScopeIntoAccessItem(scope)
            ?: return responseToken //could not parse scope, return empty token

        val clientRoleNames = getClientRoleNames(userSession, clientSession)

        //admins
        if (clientRoleNames.contains(ROLE_ADMIN)) {
            if (logger.isDebugEnabled) {
                logger.debug("Granting all access for user '${userSession.user.username}' (has role '$ROLE_ADMIN')")
            }
            responseToken.accessItems.add(accessItem) //admins can access everything
            return responseToken
        }

        //users
        if (accessItem.type == ACCESS_TYPE_REPOSITORY) {
            return handleRepositoryAccess(scope, accessItem, responseToken, userSession)
        }

        if (accessItem.type == ACCESS_TYPE_REPOSITORY_PLUGIN) {
            return handleRepositoryPluginAccess(scope, accessItem, responseToken, userSession)
        }

        if (accessItem.type == ACCESS_TYPE_REGISTRY) {
            if (logger.isDebugEnabled) {
                logger.debug("Access denied for user '${userSession.user.username}' on scope '$scope': " +
                        "Role '$ROLE_ADMIN' needed to access registry scope")
            }
            return responseToken //only admins can access scope 'registry'
        }
        if (logger.isDebugEnabled) {
            logger.debug("Access denied for user '${userSession.user.username}' on scope '$scope'")
        }
        return responseToken
    }

    private fun parseScopeIntoAccessItem(scope: String): DockerAccess? {
        return try {
            val accessItem = DockerAccess(scope)
            if (logger.isTraceEnabled) {
                logger.trace("Parsed scope '$scope' into: $accessItem")
            }
            accessItem
        } catch (e: Exception) {
            logger.warn("Could not parse scope '$scope' into access object", e)
            null
        }
    }

    private fun getClientRoleNames(
        userSession: UserSessionModel,
        clientSession: AuthenticatedClientSessionModel
    ): Collection<String> {
        return userSession.user.getClientRoleMappingsStream(clientSession.client)
            .map { it.name.lowercase() }.toList()
    }

    private fun handleRepositoryPluginAccess(
        scope: String,
        accessItem: DockerAccess,
        responseToken: DockerResponseToken,
        userSession: UserSessionModel
    ): DockerResponseToken {
        return handleRepositoryAccess(scope, accessItem, responseToken, userSession)
    }

    private fun handleRepositoryAccess(
        scope: String,
        accessItem: DockerAccess,
        responseToken: DockerResponseToken,
        userSession: UserSessionModel
    ): DockerResponseToken {

        val namespace = getRepositoryNamespace(accessItem)
        if (namespace == null) {
            if (logger.isDebugEnabled) {
                logger.debug(
                    "Access denied for user '${userSession.user.username}' on scope '$scope': " +
                            "Role '$ROLE_ADMIN' needed to access default namespace repositories"
                )
            }
            return responseToken //only admins can access default namespace repositories
        }

        val userNamespaces = getUserNamespaces(userSession).also {
            if (it.isEmpty()) {
                if (logger.isDebugEnabled) {
                    logger.debug("User '${userSession.user.username}' does not belong to any namespace (check groups)")
                }
                return responseToken
            }
        }

        if (userNamespaces.contains(namespace)) {
            // users can push and pull from their own namespaces
            if (logger.isDebugEnabled) {
                logger.debug("Granting access for user '${userSession.user.username}' on scope '$scope'")
            }
            responseToken.accessItems.add(accessItem)
            return responseToken
        }

        if (logger.isDebugEnabled) {
            logger.debug(
                "Access denied for user '${userSession.user.username}' on scope '$scope': " +
                        "Missing namespace group $GROUP_PREFIX$namespace"
            )
        }
        return responseToken
    }

    private fun getUserNamespaces(userSession: UserSessionModel): Collection<String> {
        return userSession.user.groupsStream
            .filter { it.name.startsWith(GROUP_PREFIX) }
            .map { it.name.lowercase().replace(GROUP_PREFIX, "") }.toList()
    }

    private fun getRepositoryNamespace(accessItem: DockerAccess): String? {
        val parts = accessItem.name.split("/")
        if (parts.size == 2) {
            return parts[0].lowercase()
        }
        return null
    }
}