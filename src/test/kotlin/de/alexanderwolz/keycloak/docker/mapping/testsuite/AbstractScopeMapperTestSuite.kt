package de.alexanderwolz.keycloak.docker.mapping.testsuite

import de.alexanderwolz.keycloak.docker.mapping.KeycloakGroupsAndRolesToDockerScopeMapper
import org.jboss.logging.Logger
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInfo
import org.keycloak.models.*
import org.keycloak.protocol.docker.DockerAuthV2Protocol
import org.keycloak.representations.docker.DockerResponseToken
import org.mockito.BDDMockito
import org.mockito.Mockito
import org.mockito.kotlin.given
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.assertEquals

abstract class AbstractScopeMapperTestSuite {

    companion object {
        private const val CLIENT_ID = "registry"
        private const val USER_NAME = "Johnny"
        private const val IMAGE = "image"

        //must be username in case we set the namespace scope 'username' flag
        private const val NAMESPACE = "johnny"

        // scopes can either be registry, repository or repository(plugin)
        const val SCOPE_REGISTRY_CATALOG_ALL = "registry:catalog:*"
        const val SCOPE_REGISTRY_OTHER_ALL = "registry:other:*"

        const val SCOPE_REPO_DEFAULT_ALL = "repository:$IMAGE:*"
        const val SCOPE_REPO_DEFAULT_PULL = "repository:$IMAGE:pull"
        const val SCOPE_REPO_DEFAULT_PUSH = "repository:$IMAGE:push"
        const val SCOPE_REPO_DEFAULT_DELETE = "repository:$IMAGE:delete"
        const val SCOPE_REPO_DEFAULT_PULL_PUSH = "repository:$IMAGE:pull,push"

        const val SCOPE_REPO_NAMESPACE_ALL = "repository:$NAMESPACE/$IMAGE:*"
        const val SCOPE_REPO_NAMESPACE_PULL = "repository:$NAMESPACE/$IMAGE:pull"
        const val SCOPE_REPO_NAMESPACE_PUSH = "repository:$NAMESPACE/$IMAGE:push"
        const val SCOPE_REPO_NAMESPACE_DELETE = "repository:$NAMESPACE/$IMAGE:delete"
        const val SCOPE_REPO_NAMESPACE_PULL_PUSH = "repository:$NAMESPACE/$IMAGE:pull,push"

        const val SCOPE_REPO_PLUGIN_DEFAULT_ALL = "repository(plugin):$IMAGE:*"
        const val SCOPE_REPO_PLUGIN_DEFAULT_PULL = "repository(plugin):$IMAGE:pull"
        const val SCOPE_REPO_PLUGIN_DEFAULT_PUSH = "repository(plugin):$IMAGE:push"
        const val SCOPE_REPO_PLUGIN_DEFAULT_DELETE = "repository(plugin):$IMAGE:delete"
        const val SCOPE_REPO_PLUGIN_DEFAULT_PULL_PUSH = "repository(plugin):$IMAGE:pull,push"

        const val SCOPE_REPO_PLUGIN_NAMESPACE_ALL = "repository(plugin):$NAMESPACE/$IMAGE:*"
        const val SCOPE_REPO_PLUGIN_NAMESPACE_PULL = "repository(plugin):$NAMESPACE/$IMAGE:pull"
        const val SCOPE_REPO_PLUGIN_NAMESPACE_PUSH = "repository(plugin):$NAMESPACE/$IMAGE:push"
        const val SCOPE_REPO_PLUGIN_NAMESPACE_DELETE = "repository(plugin):$NAMESPACE/$IMAGE:delete"
        const val SCOPE_REPO_PLUGIN_NAMESPACE_PULL_PUSH = "repository(plugin):$NAMESPACE/$IMAGE:pull,push"

        const val AUDIENCE_USER = KeycloakGroupsAndRolesToDockerScopeMapper.ROLE_USER
        const val AUDIENCE_EDITOR = KeycloakGroupsAndRolesToDockerScopeMapper.ROLE_EDITOR

        const val NAMESPACE_SCOPE_USERNAME = KeycloakGroupsAndRolesToDockerScopeMapper.NAMESPACE_SCOPE_USERNAME
        const val NAMESPACE_SCOPE_GROUP = KeycloakGroupsAndRolesToDockerScopeMapper.NAMESPACE_SCOPE_GROUP

        const val ROLE_EDITOR = KeycloakGroupsAndRolesToDockerScopeMapper.ROLE_EDITOR
        const val ROLE_ADMIN = KeycloakGroupsAndRolesToDockerScopeMapper.ROLE_ADMIN

        const val ACTION_PULL = KeycloakGroupsAndRolesToDockerScopeMapper.ACTION_PULL
        const val ACTION_PUSH = KeycloakGroupsAndRolesToDockerScopeMapper.ACTION_PUSH
        const val ACTION_DELETE = KeycloakGroupsAndRolesToDockerScopeMapper.ACTION_DELETE
        internal const val ACTION_ALL = KeycloakGroupsAndRolesToDockerScopeMapper.ACTION_ALL

        const val GROUP_NAMESPACE = "${KeycloakGroupsAndRolesToDockerScopeMapper.GROUP_PREFIX}$NAMESPACE"
        const val GROUP_NAMESPACE_OTHER = "${KeycloakGroupsAndRolesToDockerScopeMapper.GROUP_PREFIX}otherNamespace"
    }

    private val logger = Logger.getLogger(javaClass)

    //transformDockerResponseToken - uses responseToken, userSession and clientSession
    private lateinit var mapper: KeycloakGroupsAndRolesToDockerScopeMapper

    private lateinit var responseToken: DockerResponseToken

    private lateinit var mappingModel: ProtocolMapperModel
    private lateinit var userModel: UserModel
    private lateinit var clientModel: ClientModel

    private lateinit var session: KeycloakSession
    private lateinit var userSession: UserSessionModel
    private lateinit var clientSession: AuthenticatedClientSessionModel

    @BeforeTest
    private fun logCurrentTestMethodName(info: TestInfo) {
        logger.info("** TEST: ${info.displayName.split("$").first()}")
    }

    @AfterTest
    private fun logEmptyLine() = logger.info("")

    @Test
    @BeforeEach
    private fun setUp() {

        mapper = KeycloakGroupsAndRolesToDockerScopeMapper()

        //unused objects but necessary because of signature
        responseToken = DockerResponseToken()
        mappingModel = ProtocolMapperModel()
        session = Mockito.mock(KeycloakSession::class.java)

        userModel = Mockito.mock(UserModel::class.java)
        given(userModel.username).willReturn(USER_NAME)

        clientModel = Mockito.mock(ClientModel::class.java)
        given(clientModel.clientId).willReturn(CLIENT_ID)

        userSession = Mockito.mock(UserSessionModel::class.java)
        given(userSession.user).willReturn(userModel)
        assertEquals(USER_NAME, userSession.user.username)

        clientSession = Mockito.mock(AuthenticatedClientSessionModel::class.java)
        given(clientSession.client).willReturn(clientModel)
        assertEquals(CLIENT_ID, clientSession.client.clientId)

        setGroups()
        setRoles()
        setScope()
    }

    protected fun setGroups(vararg groupNames: String) {
        val groups = createGroupsByNames(*groupNames)
        given(userModel.groupsStream).willAnswer { groups.stream() }
        assertEquals(groups, userModel.groupsStream.toList())
    }

    protected open fun setRoles(vararg roleNames: String) {
        val roles = createClientRolesByNames(*roleNames)
        given(userModel.getClientRoleMappingsStream(clientModel)).willAnswer { roles.stream() }
    }

    protected fun setScope(scope: String = "") {
        val actualScope = scope.ifEmpty { null }
        given(clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM)).willReturn(actualScope)
        assertEquals(actualScope, clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM))
    }

    protected fun setAudience(vararg audience: String) {
        mapper.catalogAudience.clear()
        mapper.catalogAudience.addAll(audience)
    }

    protected fun setNamespaceScope(vararg namespaceScope: String) {
        mapper.namespaceScope.clear()
        mapper.namespaceScope.addAll(namespaceScope)
    }

    protected fun assertEmptyAccessItems(actualToken: DockerResponseToken = transformDockerResponseToken()) {
        assertEquals(0, actualToken.accessItems.size)
        //logger.debug("Passed ${object {}.javaClass.enclosingMethod.name}")
    }

    protected fun assertContainsOneAccessItemWithActions(
        vararg expectedActions: String,
        actualToken: DockerResponseToken = transformDockerResponseToken()
    ) {
        assertEquals(1, actualToken.accessItems.size)
        assertEquals(expectedActions.sorted(), actualToken.accessItems.first().actions.sorted())
        //logger.debug("Passed ${object {}.javaClass.enclosingMethod.name}")
    }


    /**
     *  convenience methods
     */

    private fun transformDockerResponseToken(): DockerResponseToken {
        return mapper.transformDockerResponseToken(
            responseToken, mappingModel, session, userSession, clientSession
        )
    }

    private fun createGroupsByNames(vararg names: String): Collection<GroupModel> {
        val groups = ArrayList<GroupModel>()
        names.forEach {
            val group = Mockito.mock(GroupModel::class.java)
            BDDMockito.given(group.name).willReturn(it)
            groups.add(group)
        }
        return groups
    }

    private fun createClientRolesByNames(vararg names: String): Collection<RoleModel> {
        val roles = ArrayList<RoleModel>()
        names.forEach {
            val role = Mockito.mock(RoleModel::class.java)
            BDDMockito.given(role.name).willReturn(it)
            roles.add(role)
        }
        return roles
    }

}