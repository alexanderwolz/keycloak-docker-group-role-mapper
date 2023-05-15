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

        internal const val ACTION_PULL = "pull"
        internal const val ACTION_PUSH = "push"
        internal const val ACTION_ALL = "*"

        internal const val ROLE_ADMIN = "admin"
        internal const val ROLE_PUSH = "push"
        internal const val GROUP_PREFIX = "registry-"
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

        val scope = getScopeFromSession(clientSession)
            ?: return responseToken //no scope, no worries

        val accessItem = parseScopeIntoAccessItem(scope)
            ?: return responseToken //could not parse scope, return empty token

        if (accessItem.actions.isEmpty()) {
            return responseToken // no actions given in scope
        }

        val clientRoleNames = getClientRoleNames(userSession, clientSession)

        //admins
        if (clientRoleNames.contains(ROLE_ADMIN)) {
            //admins can access everything
            //TODO shall we substitute '*' here with pull and push too?
            return allowAll(responseToken, scope, accessItem, userSession, "User has role '$ROLE_ADMIN'")
        }

        //users
        if (accessItem.type == ACCESS_TYPE_REPOSITORY) {
            return handleRepositoryAccess(responseToken, scope, clientRoleNames, accessItem, userSession)
        }

        if (accessItem.type == ACCESS_TYPE_REPOSITORY_PLUGIN) {
            return handleRepositoryPluginAccess(scope, clientRoleNames, accessItem, responseToken, userSession)
        }

        if (accessItem.type == ACCESS_TYPE_REGISTRY) {
            //only admins can access scope 'registry'
            val reason = "Role '$ROLE_ADMIN' needed to access registry scope"
            return denyAll(responseToken, scope, userSession, reason)
        }

        return denyAll(responseToken, scope, userSession, "Unsupported access type '${accessItem.type}'")
    }

    private fun getScopeFromSession(clientSession: AuthenticatedClientSessionModel): String? {
        val scope = clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM)
        if (logger.isDebugEnabled && scope == null) {
            logger.debug("Session does not contain a scope, ignoring further access check")
        }
        return scope
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

    private fun allowAll(
        responseToken: DockerResponseToken,
        scope: String,
        accessItem: DockerAccess,
        userSession: UserSessionModel,
        reason: String
    ): DockerResponseToken {
        if (logger.isDebugEnabled) {
            logger.debug("Granting access for user '${userSession.user.username}' on scope '$scope': $reason")
        }
        responseToken.accessItems.add(accessItem)
        return responseToken
    }

    private fun denyAll(
        responseToken: DockerResponseToken,
        scope: String,
        userSession: UserSessionModel,
        reason: String
    ): DockerResponseToken {
        if (logger.isDebugEnabled) {
            val username = userSession.user.username
            logger.debug("Access denied for user '$username' on scope '$scope': $reason")
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

    private fun handleRepositoryPluginAccess(
        scope: String,
        clientRoleNames: Collection<String>,
        accessItem: DockerAccess,
        responseToken: DockerResponseToken,
        userSession: UserSessionModel
    ): DockerResponseToken {
        return handleRepositoryAccess(responseToken, scope, clientRoleNames, accessItem, userSession)
    }

    private fun handleRepositoryAccess(
        responseToken: DockerResponseToken,
        scope: String,
        clientRoleNames: Collection<String>,
        accessItem: DockerAccess,
        userSession: UserSessionModel
    ): DockerResponseToken {

        val namespace = getRepositoryNamespace(accessItem)
        if (namespace == null) {
            //only admins can access default namespace repositories
            val reason = "Role '$ROLE_ADMIN' needed to access default namespace repositories"
            return denyAll(responseToken, scope, userSession, reason)
        }

        val userNamespaces = getUserNamespaces(userSession).also {
            if (it.isEmpty()) {
                val reason = "User does not belong to any namespace (check groups)"
                return denyAll(responseToken, scope, userSession, reason)
            }
        }

        return if (userNamespaces.contains(namespace)) {
            handleNamespaceRepositoryAccess(responseToken, scope, accessItem, clientRoleNames, userSession)
        } else {
            val reason = "Missing namespace group '$GROUP_PREFIX$namespace' (check groups)"
            denyAll(responseToken, scope, userSession, reason)
        }
    }

    private fun handleNamespaceRepositoryAccess(
        responseToken: DockerResponseToken,
        scope: String,
        accessItem: DockerAccess,
        clientRoleNames: Collection<String>,
        userSession: UserSessionModel
    ): DockerResponseToken {

        val requestedActions = accessItem.actions
        accessItem.actions = calculateAllowedActions(accessItem, clientRoleNames)

        if (accessItem.actions.isEmpty()) {
            return denyAll(responseToken, scope, userSession, "Missing privileges (check client roles)")
        }

        if(accessItem.actions.containsAll(requestedActions)){
            val reason = "User has privilege on all actions"
            return allowAll(responseToken, scope, accessItem, userSession, reason)
        }

        val reason = "User has privilege only on '${accessItem.actions.joinToString()}'"
        return allowAll(responseToken, scope, accessItem, userSession, reason)
    }

    internal fun calculateAllowedActions(
        accessItem: DockerAccess,
        clientRoleNames: Collection<String>
    ): List<String> {
        val allowedActions = ArrayList<String>()
        substituteActions(accessItem).forEach { action ->
            if (ACTION_PUSH == action && clientRoleNames.contains(ROLE_PUSH)) {
                allowedActions.add(action)
            }
            if (ACTION_PULL == action) {
                //all users in namespace group can pull images
                //TODO consider having a pull role?
                allowedActions.add(action)
            }
        }
        return allowedActions
    }

    // we replace '*' by pull and push, but this should normally not be the case
    // on repository types. We substitute just in case
    internal fun substituteActions(accessItem: DockerAccess): Set<String> {
        return HashSet(accessItem.actions).also { actions ->
            if (actions.contains(ACTION_ALL)) {
                actions.remove(ACTION_ALL)
                actions.add(ACTION_PULL)
                actions.add(ACTION_PUSH)
            }
        }
    }
}