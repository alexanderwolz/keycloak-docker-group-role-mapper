package de.alexanderwolz.keycloak.docker.mapping

import de.alexanderwolz.keycloak.docker.utils.MapperUtils
import org.jboss.logging.Logger
import org.keycloak.models.*
import org.keycloak.protocol.docker.DockerAuthV2Protocol
import org.keycloak.protocol.docker.mapper.DockerAuthV2AttributeMapper
import org.keycloak.protocol.docker.mapper.DockerAuthV2ProtocolMapper
import org.keycloak.representations.docker.DockerResponseToken

// reference: https://www.baeldung.com/keycloak-custom-protocol-mapper
// see also https://www.keycloak.org/docs-api/21.1.1/javadocs/org/keycloak/protocol/ProtocolMapper.html
// see also https://www.keycloak.org/docs-api/21.1.1/javadocs/org/keycloak/protocol/docker/mapper/DockerAuthV2ProtocolMapper.html
// see also https://docs.docker.com/registry/spec/auth/token/

class KeycloakGroupsAndRolesToDockerScopeMapper : DockerAuthV2ProtocolMapper(), DockerAuthV2AttributeMapper {

    private val logger = Logger.getLogger(javaClass.simpleName)

    internal var catalogAudience = getCatalogAudienceFromEnv()
    internal var namespaceScope = getNamespaceScopeFromEnv()

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

        val accessItem = parseScopeIntoAccessItem(scope) ?: return responseToken //could not parse scope

        if (accessItem.actions.isEmpty()) {
            return responseToken // no actions given in scope
        }

        val clientRoleNames = MapperUtils.getClientRoleNames(userSession.user, clientSession.client)

        return handleScopeAccess(responseToken, accessItem, userSession.user, clientRoleNames)
    }

    private fun handleScopeAccess(
        responseToken: DockerResponseToken,
        accessItem: DockerAccess,
        user: UserModel,
        clientRoleNames: Collection<String>
    ): DockerResponseToken {

        //admins
        if (clientRoleNames.contains(ROLE_ADMIN)) {
            //admins can access everything
            return allowAll(responseToken, accessItem, user, "User has role '$ROLE_ADMIN'")
        }

        //users and editors
        if (accessItem.type == ACCESS_TYPE_REGISTRY) {
            return handleRegistryAccess(responseToken, clientRoleNames, accessItem, user)
        }

        if (accessItem.type == ACCESS_TYPE_REPOSITORY) {
            return handleRepositoryAccess(responseToken, clientRoleNames, accessItem, user)
        }

        if (accessItem.type == ACCESS_TYPE_REPOSITORY_PLUGIN) {
            //handle plugins the same as normal repositories
            return handleRepositoryAccess(responseToken, clientRoleNames, accessItem, user)
        }

        return deny(responseToken, accessItem, user, "Unsupported access type '${accessItem.type}'")
    }

    private fun handleRegistryAccess(
        responseToken: DockerResponseToken,
        clientRoleNames: Collection<String>,
        accessItem: DockerAccess,
        user: UserModel
    ): DockerResponseToken {
        if (accessItem.name == NAME_CATALOG) {
            if (isAllowedToAccessRegistryCatalogScope(clientRoleNames)) {
                val reason = "Allowed by catalog audience '$catalogAudience'"
                return allowAll(responseToken, accessItem, user, reason)
            }
            val reason = if (clientRoleNames.contains(ROLE_EDITOR)) {
                "Role '$ROLE_ADMIN' or \$${KEY_REGISTRY_CATALOG_AUDIENCE}='$AUDIENCE_EDITOR' needed to access catalog"
            } else {
                "Role '$ROLE_ADMIN' or \$${KEY_REGISTRY_CATALOG_AUDIENCE}='$AUDIENCE_USER' needed to access catalog"
            }
            return deny(responseToken, accessItem, user, reason)
        }
        //only admins can access scope 'registry'
        val reason = "Role '$ROLE_ADMIN' needed to access registry scope"
        return deny(responseToken, accessItem, user, reason)
    }

    private fun isAllowedToAccessRegistryCatalogScope(clientRoleNames: Collection<String>): Boolean {
        return catalogAudience == AUDIENCE_USER
                || (catalogAudience == AUDIENCE_EDITOR && clientRoleNames.contains(ROLE_EDITOR))
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


    private fun allowAll(
        responseToken: DockerResponseToken,
        accessItem: DockerAccess,
        user: UserModel,
        reason: String
    ): DockerResponseToken {
        if (logger.isDebugEnabled) {
            logger.debug("Granting access for user '${user.username}' on scope '${accessItem.scope}': $reason")
        }
        responseToken.accessItems.add(accessItem)
        return responseToken
    }

    private fun allowWithActions(
        responseToken: DockerResponseToken,
        accessItem: DockerAccess,
        allowedActions: List<String>,
        user: UserModel,
        reason: String
    ): DockerResponseToken {
        if (logger.isDebugEnabled) {
            logger.debug("Granting access for user '${user.username}' on scope '${accessItem.scope}': $reason")
        }
        accessItem.actions = allowedActions
        responseToken.accessItems.add(accessItem)
        return responseToken
    }

    private fun deny(
        responseToken: DockerResponseToken,
        accessItem: DockerAccess,
        user: UserModel,
        reason: String = ""
    ): DockerResponseToken {
        var message = "Access denied for user '${user.username}' on scope '${accessItem.scope}'"
        if (reason.isNotEmpty()) {
            message += ": $reason"
        }
        logger.warn(message)
        return responseToken
    }

    private fun handleRepositoryAccess(
        responseToken: DockerResponseToken,
        clientRoleNames: Collection<String>,
        accessItem: DockerAccess,
        user: UserModel
    ): DockerResponseToken {

        val namespace = MapperUtils.getNamespaceFromRepositoryName(accessItem.name) ?: return deny(
            responseToken, accessItem, user, "Role '$ROLE_ADMIN' needed to access default namespace repositories"
        )

        if (namespaceScope.contains(NAMESPACE_SCOPE_USERNAME) && isUsernameRepository(namespace, user.username)) {
            //user's own repository, will have all access
            val allowedActions = MapperUtils.substituteRequestedActions(accessItem.actions)
            return allowWithActions(responseToken, accessItem, allowedActions, user, "Accessing user's own namespace")
        }

        if (namespaceScope.contains(NAMESPACE_SCOPE_DOMAIN) && isDomainRepository(namespace, user.email)) {
            return handleNamespaceRepositoryAccess(responseToken, accessItem, clientRoleNames, user)
        }

        if (namespaceScope.contains(NAMESPACE_SCOPE_SLD) && isSecondLevelDomainRepository(namespace, user.email)) {
            return handleNamespaceRepositoryAccess(responseToken, accessItem, clientRoleNames, user)
        }

        if (namespaceScope.contains(NAMESPACE_SCOPE_GROUP)) {
            val namespacesFromGroups = MapperUtils.getUserNamespacesFromGroups(user).also {
                if (it.isEmpty()) {
                    val reason = "User does not belong to any namespace - check groups"
                    return deny(responseToken, accessItem, user, reason)
                }
            }
            if (namespacesFromGroups.contains(namespace)) {
                return handleNamespaceRepositoryAccess(responseToken, accessItem, clientRoleNames, user)
            }
            val reason = "Missing namespace group '$GROUP_PREFIX$namespace' - check groups"
            return deny(responseToken, accessItem, user, reason)
        }

        val reason = "User does not belong to namespace '$namespace' either by group nor username nor domain"
        return deny(responseToken, accessItem, user, reason)
    }

    private fun handleNamespaceRepositoryAccess(
        responseToken: DockerResponseToken,
        accessItem: DockerAccess,
        clientRoleNames: Collection<String>,
        user: UserModel
    ): DockerResponseToken {

        val requestedActions = accessItem.actions
        val allowedActions = MapperUtils.filterAllowedActions(requestedActions, clientRoleNames)

        if (allowedActions.isEmpty()) {
            val reason = "Missing privileges for actions [${requestedActions.joinToString()}] - check client roles"
            return deny(responseToken, accessItem, user, reason)
        }

        if (MapperUtils.hasAllPrivileges(allowedActions, requestedActions)) {
            val reason = "User has privilege on all actions"
            return allowWithActions(responseToken, accessItem, allowedActions, user, reason)
        }

        val reason = "User has privilege only on [${allowedActions.joinToString()}]"
        return allowWithActions(responseToken, accessItem, allowedActions, user, reason)
    }

    private fun isUsernameRepository(namespace: String, username: String): Boolean {
        return namespace == username.lowercase()
    }

    private fun isDomainRepository(namespace: String, email: String): Boolean {
        return namespace == MapperUtils.getDomainFromEmail(email)
    }

    private fun isSecondLevelDomainRepository(namespace: String, email: String): Boolean {
        return namespace == MapperUtils.getSecondLevelDomainFromEmail(email)
    }

    private fun getEnv(key: String): String? {
        return try {
            System.getenv()[key]
        } catch (e: Exception) {
            logger.error("Could not access System Environment", e)
            null
        }
    }


    private fun getCatalogAudienceFromEnv(): String {
        return getEnv(KEY_REGISTRY_CATALOG_AUDIENCE)?.let {
            val audienceString = it.lowercase()
            if (audienceString == AUDIENCE_USER) {
                return@let AUDIENCE_USER
            }
            if (audienceString == AUDIENCE_EDITOR) {
                return@let AUDIENCE_EDITOR
            }
            return@let AUDIENCE_ADMIN
        } ?: AUDIENCE_ADMIN
    }

    private fun getNamespaceScopeFromEnv(): Set<String> {
        return getEnv(KEY_REGISTRY_NAMESPACE_SCOPE)?.let { scopeString ->
            val scopes = scopeString.split(",").map { it.lowercase() }
                .filter {
                    it == NAMESPACE_SCOPE_GROUP
                            || it == NAMESPACE_SCOPE_USERNAME
                            || it == NAMESPACE_SCOPE_DOMAIN
                            || it == NAMESPACE_SCOPE_SLD
                }
            if (scopes.isEmpty()) {
                logger.warn("Empty or unsupported config values for \$$KEY_REGISTRY_NAMESPACE_SCOPE: $scopeString")
                logger.warn("Resetting \$$KEY_REGISTRY_NAMESPACE_SCOPE to default: $NAMESPACE_SCOPE_DEFAULT")
                NAMESPACE_SCOPE_DEFAULT
            }
            scopes.toSet()
        } ?: NAMESPACE_SCOPE_DEFAULT
    }

    companion object {
        private const val PROVIDER_ID = "docker-v2-allow-by-groups-and-roles-mapper"
        private const val DISPLAY_TYPE = "Allow by Groups and Roles"
        private const val HELP_TEXT = "Maps Docker v2 scopes by user roles and groups"

        internal const val GROUP_PREFIX = "registry-"

        //anybody with access to namespace repo is considered 'user'
        private const val ROLE_USER = "user"
        internal const val ROLE_EDITOR = "editor"
        internal const val ROLE_ADMIN = "admin"

        //can be 'user' or 'editor' or both separated by ','
        internal const val KEY_REGISTRY_CATALOG_AUDIENCE = "REGISTRY_CATALOG_AUDIENCE"
        internal const val AUDIENCE_USER = ROLE_USER
        internal const val AUDIENCE_EDITOR = ROLE_EDITOR
        internal const val AUDIENCE_ADMIN = ROLE_ADMIN

        internal const val KEY_REGISTRY_NAMESPACE_SCOPE = "REGISTRY_NAMESPACE_SCOPE"
        internal const val NAMESPACE_SCOPE_USERNAME = "username"
        internal const val NAMESPACE_SCOPE_GROUP = "group"
        internal const val NAMESPACE_SCOPE_DOMAIN = "domain"
        internal const val NAMESPACE_SCOPE_SLD = "sld"
        internal val NAMESPACE_SCOPE_DEFAULT = setOf(NAMESPACE_SCOPE_GROUP)

        //see also https://docs.docker.com/registry/spec/auth/scope/
        private const val ACCESS_TYPE_REGISTRY = "registry"
        private const val ACCESS_TYPE_REPOSITORY = "repository"
        private const val ACCESS_TYPE_REPOSITORY_PLUGIN = "repository(plugin)"

        private const val NAME_CATALOG = "catalog"

        internal const val ACTION_PULL = "pull"
        internal const val ACTION_PUSH = "push"
        internal const val ACTION_DELETE = "delete"
        internal const val ACTION_ALL = "*"
        internal val ACTION_ALL_SUBSTITUTE = listOf(ACTION_PULL, ACTION_PUSH, ACTION_DELETE)
    }

    // cache plain scope into DockerAccess class
    private class DockerAccess(val scope: String) : org.keycloak.representations.docker.DockerAccess(scope)
}