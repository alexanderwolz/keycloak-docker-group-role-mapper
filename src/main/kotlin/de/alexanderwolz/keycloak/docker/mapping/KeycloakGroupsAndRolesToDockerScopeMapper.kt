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

    private val logger = Logger.getLogger(javaClass.simpleName)

    internal val catalogAudience = HashSet<String>()
    internal val namespaceScope = HashSet<String>()

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

        val scope = getScopeFromSession(clientSession) ?: return responseToken //no scope, no worries

        val accessItem =
            parseScopeIntoAccessItem(scope) ?: return responseToken //could not parse scope, return empty token

        if (accessItem.actions.isEmpty()) {
            return responseToken // no actions given in scope
        }

        val clientRoleNames = getClientRoleNames(userSession, clientSession)

        //admins
        if (clientRoleNames.contains(ROLE_ADMIN)) {
            //admins can access everything
            return allowAll(responseToken, scope, accessItem, userSession, "User has role '$ROLE_ADMIN'")
        }

        //users
        if (accessItem.type == ACCESS_TYPE_REGISTRY) {
            if (accessItem.name == NAME_CATALOG) {
                return handleRegistryCatalogAccess(responseToken, scope, accessItem, clientRoleNames, userSession)
            }
            //only admins can access scope 'registry'
            val reason = "Role '$ROLE_ADMIN' needed to access registry scope"
            return denyAll(responseToken, scope, userSession, reason)
        }

        if (accessItem.type == ACCESS_TYPE_REPOSITORY) {
            return handleRepositoryAccess(responseToken, scope, clientRoleNames, accessItem, userSession)
        }

        if (accessItem.type == ACCESS_TYPE_REPOSITORY_PLUGIN) {
            return handleRepositoryPluginAccess(scope, clientRoleNames, accessItem, responseToken, userSession)
        }

        return denyAll(responseToken, scope, userSession, "Unsupported access type '${accessItem.type}'")
    }

    private fun handleRegistryCatalogAccess(
        responseToken: DockerResponseToken,
        scope: String,
        accessItem: DockerAccess,
        clientRoleNames: Collection<String>,
        userSession: UserSessionModel
    ): DockerResponseToken {
        if (isAllowedToAccessCategory(clientRoleNames)) {
            val reason = "Allowed by catalog audience '${catalogAudience.joinToString()}'"
            return allowAll(responseToken, scope, accessItem, userSession, reason)
        }
        val reason = if (clientRoleNames.contains(ROLE_EDITOR)) {
            "Role '$ROLE_ADMIN' or \$${KEY_REGISTRY_CATALOG_AUDIENCE}='$ROLE_EDITOR' needed to access catalog"
        } else {
            "Role '$ROLE_ADMIN' or \$${KEY_REGISTRY_CATALOG_AUDIENCE}='$ROLE_USER' needed to access catalog"
        }
        return denyAll(responseToken, scope, userSession, reason)
    }

    private fun isAllowedToAccessCategory(clientRoleNames: Collection<String>): Boolean {
        if (catalogAudience.contains(ROLE_USER)) {
            return true
        }
        if (catalogAudience.contains(ROLE_EDITOR) && clientRoleNames.contains(ROLE_EDITOR)) {
            return true
        }
        return false
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
        userSession: UserSessionModel, clientSession: AuthenticatedClientSessionModel
    ): Collection<String> {
        return userSession.user.getClientRoleMappingsStream(clientSession.client).map { it.name.lowercase() }.toList()
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
        responseToken: DockerResponseToken, scope: String, userSession: UserSessionModel, reason: String = ""
    ): DockerResponseToken {
        if (logger.isDebugEnabled) {
            val username = userSession.user.username
            var message = "Access denied for user '$username' on scope '$scope'"
            if (reason.isNotEmpty()) {
                message += ": $reason"
            }
            logger.debug(message)
        }
        return responseToken
    }

    private fun getUserNamespacesFromGroups(userSession: UserSessionModel): Collection<String> {
        return userSession.user.groupsStream.filter { it.name.startsWith(GROUP_PREFIX) }
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

        val namespace = getRepositoryNamespace(accessItem) ?: return denyAll(
            responseToken, scope, userSession, "Role '$ROLE_ADMIN' needed to access default namespace repositories"
        )

        if (namespaceScope.contains(NAMESPACE_SCOPE_USERNAME)) {
            if (userSession.user.username.lowercase() == namespace) {
                return handleNamespaceRepositoryAccess(responseToken, scope, accessItem, clientRoleNames, userSession)
            }
        }

        if (namespaceScope.contains(NAMESPACE_SCOPE_GROUP)) {
            val userNamespaces = getUserNamespacesFromGroups(userSession).also {
                if (it.isEmpty()) {
                    val reason = "User does not belong to any namespace - check groups"
                    return denyAll(responseToken, scope, userSession, reason)
                }
            }
            if (userNamespaces.contains(namespace)) {
                return handleNamespaceRepositoryAccess(responseToken, scope, accessItem, clientRoleNames, userSession)
            }
            val reason = "Missing namespace group '$GROUP_PREFIX$namespace' - check groups"
            return denyAll(responseToken, scope, userSession, reason)
        }

        val reason = "User does not belong to namespace '$namespace' either by group nor username"
        return denyAll(responseToken, scope, userSession, reason)
    }

    private fun handleNamespaceRepositoryAccess(
        responseToken: DockerResponseToken,
        scope: String,
        accessItem: DockerAccess,
        clientRoleNames: Collection<String>,
        userSession: UserSessionModel
    ): DockerResponseToken {

        val requestedActions = accessItem.actions
        accessItem.actions = calculateAllowedActions(accessItem, clientRoleNames, userSession.user.username)

        if (accessItem.actions.isEmpty()) {
            return denyAll(
                responseToken,
                scope,
                userSession,
                "Missing privileges for actions [${requestedActions.joinToString()}] - check client roles"
            )
        }

        if (hasAllPrivileges(accessItem, requestedActions)) {
            val reason = "User has privilege on all actions"
            return allowAll(responseToken, scope, accessItem, userSession, reason)
        }

        val reason = "User has privilege only on [${accessItem.actions.joinToString()}]"
        return allowAll(responseToken, scope, accessItem, userSession, reason)
    }

    private fun hasAllPrivileges(accessItem: DockerAccess, requestedActions: Collection<String>): Boolean {
        return isSubstituteWithAllActions(accessItem, requestedActions) || accessItem.actions.containsAll(
            requestedActions
        )
    }

    private fun isSubstituteWithAllActions(accessItem: DockerAccess, requestedActions: Collection<String>): Boolean {
        return requestedActions.size == 1 && requestedActions.first() == ACTION_ALL && accessItem.actions.containsAll(
            ALL_ACTIONS
        )
    }

    internal fun calculateAllowedActions(
        accessItem: DockerAccess,
        clientRoleNames: Collection<String>,
        username: String
    ): List<String> {
        val allowedActions = ArrayList<String>()
        val shallAddUserAction = shallAddUserAction(accessItem, clientRoleNames, username)
        substituteActions(accessItem).forEach { action ->
            if (ACTION_PUSH == action && shallAddUserAction) {
                allowedActions.add(action)
            }
            if (ACTION_DELETE == action && shallAddUserAction) {
                allowedActions.add(action)
            }
            if (ACTION_PULL == action) {
                //all users in namespace group can pull images (read only by default)
                allowedActions.add(action)
            }
        }
        return allowedActions
    }

    // add PUSH and DELETE if namespace scope is set to 'username' or if user is 'editor'
    private fun shallAddUserAction(
        accessItem: DockerAccess, clientRoleNames: Collection<String>, username: String
    ): Boolean {
        return clientRoleNames.contains(ROLE_EDITOR) || isUserRepository(accessItem, username)
    }

    private fun isUserRepository(accessItem: DockerAccess, username: String): Boolean {
        if (namespaceScope.contains(NAMESPACE_SCOPE_USERNAME)) {
            val namespace = getRepositoryNamespace(accessItem) ?: return false
            return namespace == username.lowercase()
        }
        return false
    }

    // replaces '*' by pull, push and delete (should not be the case on repository types)
    internal fun substituteActions(accessItem: DockerAccess): Set<String> {
        return HashSet(accessItem.actions).also { actions ->
            if (actions.contains(ACTION_ALL)) {
                actions.remove(ACTION_ALL)
                actions.add(ACTION_PULL)
                actions.add(ACTION_PUSH)
                actions.add(ACTION_DELETE)
            }
        }
    }

    private val environment: Map<String, String> = try {
        System.getenv()
    } catch (e: Exception) {
        emptyMap()
    }

    init {
        environment[KEY_REGISTRY_CATALOG_AUDIENCE]?.let { audienceString ->
            val configValues = audienceString.split(",")
            catalogAudience.addAll(configValues.map { it.lowercase() }.filter {
                it == ROLE_USER || it == ROLE_EDITOR
            })
        } ?: catalogAudience.clear()

        environment[KEY_REGISTRY_NAMESPACE]?.let { scopeString ->
            val configValues = scopeString.split(",")
            namespaceScope.addAll(configValues.map { it.lowercase() }.filter {
                it == NAMESPACE_SCOPE_GROUP || it == NAMESPACE_SCOPE_USERNAME
            })
            if(namespaceScope.isEmpty()){
                logger.warn("Empty or unsupported config values for \$$KEY_REGISTRY_NAMESPACE: $scopeString")
                logger.warn("Resetting \$$KEY_REGISTRY_NAMESPACE to default: $NAMESPACE_SCOPE_GROUP")
                namespaceScope.addAll(setOf(NAMESPACE_SCOPE_GROUP))
            }
        } ?: namespaceScope.addAll(setOf(NAMESPACE_SCOPE_GROUP))
    }

    companion object {
        private const val PROVIDER_ID = "docker-v2-allow-by-groups-and-roles-mapper"
        private const val DISPLAY_TYPE = "Allow by Groups and Roles"
        private const val HELP_TEXT = "Maps Docker v2 scopes by user roles and groups"

        //can be 'user' or 'editor' or both separated by ','
        internal const val KEY_REGISTRY_CATALOG_AUDIENCE = "REGISTRY_CATALOG_AUDIENCE"

        //can be 'username' or 'group' or both separated by ','
        internal const val KEY_REGISTRY_NAMESPACE = "REGISTRY_NAMESPACE_SCOPE"

        //see also https://docs.docker.com/registry/spec/auth/scope/
        private const val ACCESS_TYPE_REGISTRY = "registry"
        private const val ACCESS_TYPE_REPOSITORY = "repository"
        private const val ACCESS_TYPE_REPOSITORY_PLUGIN = "repository(plugin)"

        private const val NAME_CATALOG = "catalog"

        internal const val ACTION_PULL = "pull"
        internal const val ACTION_PUSH = "push"
        internal const val ACTION_DELETE = "delete"
        internal const val ACTION_ALL = "*"

        private val ALL_ACTIONS = setOf(ACTION_PULL, ACTION_PUSH, ACTION_DELETE)

        //anybody with access to namespace repo is considered 'user'
        internal const val ROLE_USER = "user"
        internal const val ROLE_EDITOR = "editor"
        internal const val ROLE_ADMIN = "admin"

        internal const val NAMESPACE_SCOPE_USERNAME = "username"
        internal const val NAMESPACE_SCOPE_GROUP = "group"

        internal const val GROUP_PREFIX = "registry-"
    }
}