package de.alexanderwolz.keycloak.docker.mapping

import org.jboss.logging.Logger
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.keycloak.models.*
import org.keycloak.protocol.docker.DockerAuthV2Protocol
import org.keycloak.representations.docker.DockerAccess
import org.keycloak.representations.docker.DockerResponseToken
import org.mockito.BDDMockito.given
import org.mockito.Mockito
import kotlin.test.assertEquals


class KeycloakGroupsAndRolesToDockerScopeMapperTest {

    companion object {
        private const val CLIENT_ID = "registry"
        private const val USER_NAME = "john"

        private const val SCOPE_REGISTRY_CATALOG = "registry:catalog:*"
        private const val SCOPE_REPOSITORY = "repository:image:*"
        private const val SCOPE_REPOSITORY_NAMESPACE = "repository:namespace/image:*"
        private const val SCOPE_REPOSITORY_PLUGIN = "repository(plugin):image:*"
        private const val SCOPE_REPOSITORY_PLUGIN_NAMESPACE = "repository(plugin):namespace/image:*"

        private const val ROLE_ADMIN = "admin"
        private const val GROUP_NAMESPACE = "registry-namespace"
    }

    private val logger = Logger.getLogger(javaClass)

    //transformDockerResponseToken - uses responseToken, userSession and clientSession
    private val mapper = KeycloakGroupsAndRolesToDockerScopeMapper()

    private lateinit var responseToken: DockerResponseToken

    private lateinit var mappingModel: ProtocolMapperModel
    private lateinit var userModel: UserModel
    private lateinit var clientModel: ClientModel

    private lateinit var session: KeycloakSession
    private lateinit var userSession: UserSessionModel
    private lateinit var clientSession: AuthenticatedClientSessionModel

    @Test
    @BeforeEach
    fun setUp() {

        userModel = Mockito.mock(UserModel::class.java)
        given(userModel.username).willReturn(USER_NAME)

        clientModel = Mockito.mock(ClientModel::class.java)
        clientModel.clientId = CLIENT_ID

        responseToken = DockerResponseToken()
        mappingModel = ProtocolMapperModel()
        session = Mockito.mock(KeycloakSession::class.java)

        userSession = Mockito.mock(UserSessionModel::class.java)
        given(userSession.user).willReturn(userModel)
        assertEquals(USER_NAME, userSession.user.username)

        clientSession = Mockito.mock(AuthenticatedClientSessionModel::class.java)
        given(clientSession.client).willReturn(clientModel)
    }

    private fun logCurrentTestMethodName() {
        val methodName = Thread.currentThread().stackTrace[2].methodName
        logger.info(methodName)
    }

    private fun createGroupsByNames(vararg names: String): Collection<GroupModel> {
        val groups = ArrayList<GroupModel>()
        names.forEach {
            val group = Mockito.mock(GroupModel::class.java)
            given(group.name).willReturn(it)
            groups.add(group)
        }
        return groups
    }

    private fun createClientRolesByNames(vararg names: String): Collection<RoleModel> {
        val roles = ArrayList<RoleModel>()
        names.forEach {
            val role = Mockito.mock(RoleModel::class.java)
            given(role.name).willReturn(it)
            roles.add(role)
        }
        return roles
    }

    @Test
    fun testTokenForUserWithoutGroupsOrRolesOnEmptyScope() {

        logCurrentTestMethodName()

        given(clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM)).willReturn(null)
        assertEquals(null, clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM))

        val actualToken =
            mapper.transformDockerResponseToken(responseToken, mappingModel, session, userSession, clientSession)
        assertEquals(0, actualToken.accessItems.size)
    }

    @Test
    fun testTokenForUserWithoutGroupsOrRolesOnRegistryScope() {

        logCurrentTestMethodName()

        val expectedScope = SCOPE_REGISTRY_CATALOG
        given(clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM)).willReturn(expectedScope)
        assertEquals(expectedScope, clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM))

        val actualToken =
            mapper.transformDockerResponseToken(responseToken, mappingModel, session, userSession, clientSession)
        assertEquals(0, actualToken.accessItems.size)
    }

    @Test
    fun testTokenForUserWithoutGroupsOrRolesOnRepositoryPluginScopeWithNamespace() {

        logCurrentTestMethodName()

        val expectedScope = SCOPE_REPOSITORY_PLUGIN
        given(clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM)).willReturn(expectedScope)
        assertEquals(expectedScope, clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM))

        val actualToken =
            mapper.transformDockerResponseToken(responseToken, mappingModel, session, userSession, clientSession)
        assertEquals(0, actualToken.accessItems.size)
    }

    @Test
    fun testTokenForUserWithoutGroupsOrRolesOnRepositoryPluginScopeWithoutNamespace() {

        logCurrentTestMethodName()

        val expectedScope = SCOPE_REPOSITORY_PLUGIN_NAMESPACE
        given(clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM)).willReturn(expectedScope)
        assertEquals(expectedScope, clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM))

        val actualToken =
            mapper.transformDockerResponseToken(responseToken, mappingModel, session, userSession, clientSession)
        assertEquals(0, actualToken.accessItems.size)
    }

    @Test
    fun testTokenForUserWithoutGroupsOrRolesOnRepositoryScopeWithNamespace() {

        logCurrentTestMethodName()

        val expectedScope = SCOPE_REPOSITORY_NAMESPACE
        given(clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM)).willReturn(expectedScope)
        assertEquals(expectedScope, clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM))

        val actualToken =
            mapper.transformDockerResponseToken(responseToken, mappingModel, session, userSession, clientSession)
        assertEquals(0, actualToken.accessItems.size)
    }

    @Test
    fun testTokenForUserWithoutGroupsOrRolesOnRepositoryScopeWithoutNamespace() {

        logCurrentTestMethodName()

        val expectedScope = SCOPE_REPOSITORY
        given(clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM)).willReturn(expectedScope)
        assertEquals(expectedScope, clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM))

        val actualToken =
            mapper.transformDockerResponseToken(responseToken, mappingModel, session, userSession, clientSession)
        assertEquals(0, actualToken.accessItems.size)
    }

    @Test
    fun testTokenForUserWithOtherGroupsAndNoRolesOnRepositoryScopeWithoutNamespace() {

        logCurrentTestMethodName()

        val expectedScope = SCOPE_REPOSITORY_NAMESPACE
        given(clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM)).willReturn(expectedScope)
        assertEquals(expectedScope, clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM))

        val groups = createGroupsByNames("role-example")
        given(userModel.groupsStream).willAnswer { groups.stream() }
        assertEquals(groups, userModel.groupsStream.toList())

        val actualToken =
            mapper.transformDockerResponseToken(responseToken, mappingModel, session, userSession, clientSession)
        assertEquals(0, actualToken.accessItems.size)
    }

    @Test
    fun testTokenForUserWithNamespaceGroupsAndNoRolesOnRepositoryScopeWithNamespace() {

        logCurrentTestMethodName()

        val expectedScope = SCOPE_REPOSITORY_NAMESPACE
        given(clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM)).willReturn(expectedScope)
        assertEquals(expectedScope, clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM))

        val groups = createGroupsByNames(GROUP_NAMESPACE)
        given(userModel.groupsStream).willAnswer { groups.stream() }
        assertEquals(groups, userModel.groupsStream.toList())

        val actualToken =
            mapper.transformDockerResponseToken(responseToken, mappingModel, session, userSession, clientSession)
        assertEquals(1, actualToken.accessItems.size)
        val expectedAccessItem = DockerAccess(clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM))
        assertEquals(expectedAccessItem, actualToken.accessItems.first())
    }

    //ADMIN TESTS

    @Test
    fun testTokenForUserWithAdminRoleOnRegistryScopeWithNamespace() {

        logCurrentTestMethodName()

        val expectedScope = SCOPE_REGISTRY_CATALOG
        given(clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM)).willReturn(expectedScope)
        assertEquals(expectedScope, clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM))

        val roles = createClientRolesByNames(ROLE_ADMIN)
        given(userModel.getClientRoleMappingsStream(clientModel)).willAnswer { roles.stream() }

        val actualToken =
            mapper.transformDockerResponseToken(responseToken, mappingModel, session, userSession, clientSession)
        assertEquals(1, actualToken.accessItems.size)
        assertEquals(DockerAccess(expectedScope), actualToken.accessItems.first())
    }

    @Test
    fun testTokenForUserWithAdminRoleOnRepositoryScopeWithoutNamespace() {

        logCurrentTestMethodName()

        val expectedScope = SCOPE_REPOSITORY
        given(clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM)).willReturn(expectedScope)
        assertEquals(expectedScope, clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM))

        val roles = createClientRolesByNames(ROLE_ADMIN)
        given(userModel.getClientRoleMappingsStream(clientModel)).willAnswer { roles.stream() }

        val actualToken =
            mapper.transformDockerResponseToken(responseToken, mappingModel, session, userSession, clientSession)
        assertEquals(1, actualToken.accessItems.size)
        assertEquals(DockerAccess(expectedScope), actualToken.accessItems.first())
    }

    @Test
    fun testTokenForUserWithAdminRoleOnRepositoryScopeWithNamespace() {

        logCurrentTestMethodName()

        val expectedScope = SCOPE_REPOSITORY_NAMESPACE
        given(clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM)).willReturn(expectedScope)
        assertEquals(expectedScope, clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM))

        val roles = createClientRolesByNames(ROLE_ADMIN)
        given(userModel.getClientRoleMappingsStream(clientModel)).willAnswer { roles.stream() }

        val actualToken =
            mapper.transformDockerResponseToken(responseToken, mappingModel, session, userSession, clientSession)
        assertEquals(1, actualToken.accessItems.size)
        assertEquals(DockerAccess(expectedScope), actualToken.accessItems.first())
    }

    @Test
    fun testTokenForUserWithAdminRoleOnRepositoryPluginScopeWithoutNamespace() {

        logCurrentTestMethodName()

        val expectedScope = SCOPE_REPOSITORY_PLUGIN
        given(clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM)).willReturn(expectedScope)
        assertEquals(expectedScope, clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM))

        val roles = createClientRolesByNames(ROLE_ADMIN)
        given(userModel.getClientRoleMappingsStream(clientModel)).willAnswer { roles.stream() }

        val actualToken =
            mapper.transformDockerResponseToken(responseToken, mappingModel, session, userSession, clientSession)
        assertEquals(1, actualToken.accessItems.size)
        assertEquals(DockerAccess(expectedScope), actualToken.accessItems.first())
    }

    @Test
    fun testTokenForUserWithAdminRoleOnRepositoryPluginScopeWithNamespace() {

        logCurrentTestMethodName()

        val expectedScope = SCOPE_REPOSITORY_PLUGIN_NAMESPACE
        given(clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM)).willReturn(expectedScope)
        assertEquals(expectedScope, clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM))

        val roles = createClientRolesByNames(ROLE_ADMIN)
        given(userModel.getClientRoleMappingsStream(clientModel)).willAnswer { roles.stream() }

        val actualToken =
            mapper.transformDockerResponseToken(responseToken, mappingModel, session, userSession, clientSession)
        assertEquals(1, actualToken.accessItems.size)
        assertEquals(DockerAccess(expectedScope), actualToken.accessItems.first())
    }

}