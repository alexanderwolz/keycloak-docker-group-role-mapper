package de.alexanderwolz.keycloak.docker.mapping

//renames import for better readability
import de.alexanderwolz.keycloak.docker.mapping.test.utils.TestUtils
import org.jboss.logging.Logger
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.keycloak.models.*
import org.keycloak.protocol.docker.DockerAuthV2Protocol
import org.keycloak.representations.docker.DockerResponseToken
import org.mockito.BDDMockito.given
import org.mockito.Mockito
import kotlin.test.assertEquals
import de.alexanderwolz.keycloak.docker.mapping.KeycloakGroupsAndRolesToDockerScopeMapper as MapperToTest


// Tests constellations of docker tokens according to scope, groups and roles
internal class ScopeMapperTestSuite {

    companion object {
        private const val CLIENT_ID = "registry"
        private const val USER_NAME = "user"
        private const val IMAGE = "image"
        private const val NAMESPACE = "namespace"

        private const val SCOPE_REGISTRY_CATALOG_ALL = "registry:catalog:*"

        private const val SCOPE_REPO_ALL = "repository:${IMAGE}:*"
        private const val SCOPE_REPO_PUSH = "repository:${IMAGE}:push"
        private const val SCOPE_REPO_PULL = "repository:${IMAGE}:pull"
        private const val SCOPE_REPO_PULL_PUSH = "repository:${IMAGE}:pull,push"

        private const val SCOPE_REPO_NAMESPACE_ALL = "repository:${NAMESPACE}/${IMAGE}:*"
        private const val SCOPE_REPO_NAMESPACE_PUSH = "repository:${NAMESPACE}/${IMAGE}:push"
        private const val SCOPE_REPO_NAMESPACE_PULL = "repository:${NAMESPACE}/${IMAGE}:pull"
        private const val SCOPE_REPO_NAMESPACE_PULL_PUSH = "repository:${NAMESPACE}/${IMAGE}:pull,push"

        private const val SCOPE_REPO_PLUGIN_ALL = "repository(plugin):${IMAGE}:*"
        private const val SCOPE_REPO_PLUGIN_PUSH = "repository(plugin):${IMAGE}:push"
        private const val SCOPE_REPO_PLUGIN_PULL = "repository(plugin):${IMAGE}:pull"
        private const val SCOPE_REPO_PLUGIN_PULL_PUSH = "repository(plugin):${IMAGE}:pull,push"

        private const val SCOPE_REPO_PLUGIN_NAMESPACE_ALL = "repository(plugin):${NAMESPACE}/${IMAGE}:*"
        private const val SCOPE_REPO_PLUGIN_NAMESPACE_PUSH = "repository(plugin):${NAMESPACE}/${IMAGE}:push"
        private const val SCOPE_REPO_PLUGIN_NAMESPACE_PULL = "repository(plugin):${NAMESPACE}/${IMAGE}:pull"
        private const val SCOPE_REPO_PLUGIN_NAMESPACE_PULL_PUSH = "repository(plugin):${NAMESPACE}/${IMAGE}:pull,push"

        private const val ROLE_USER = MapperToTest.ROLE_USER
        private const val ROLE_EDITOR = MapperToTest.ROLE_EDITOR
        private const val ROLE_ADMIN = MapperToTest.ROLE_ADMIN

        private const val ACTION_PULL = MapperToTest.ACTION_PULL
        private const val ACTION_PUSH = MapperToTest.ACTION_PUSH
        private const val ACTION_DELETE = MapperToTest.ACTION_DELETE
        internal const val ACTION_ALL = MapperToTest.ACTION_ALL

        private const val GROUP_NAMESPACE = "${MapperToTest.GROUP_PREFIX}${NAMESPACE}"
        private const val GROUP_NAMESPACE_OTHER = "${MapperToTest.GROUP_PREFIX}otherNamespace"
    }

    private val logger = Logger.getLogger(javaClass)

    //transformDockerResponseToken - uses responseToken, userSession and clientSession
    private lateinit var mapper: MapperToTest

    private lateinit var responseToken: DockerResponseToken

    private lateinit var mappingModel: ProtocolMapperModel
    private lateinit var userModel: UserModel
    private lateinit var clientModel: ClientModel

    private lateinit var session: KeycloakSession
    private lateinit var userSession: UserSessionModel
    private lateinit var clientSession: AuthenticatedClientSessionModel

    @Test
    @BeforeEach
    private fun setUp() {

        mapper = MapperToTest()

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
    }

    /**
     *  convenience methods
     */

    private fun logCurrentTestMethodName() {
        val methodName = Thread.currentThread().stackTrace[3].methodName
        logger.info("TEST: $methodName")
    }

    private fun transformDockerResponseToken(): DockerResponseToken {
        return mapper.transformDockerResponseToken(responseToken, mappingModel, session, userSession, clientSession)
    }

    /**
     * Structuring Unit Tests
     */

    @Nested
    inner class UserTests {

        @Test
        internal fun user_without_groups_and_without_roles_on_empty_scope() {

            logCurrentTestMethodName()

            given(clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM)).willReturn(null)
            assertEquals(null, clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM))

            val actualToken = transformDockerResponseToken()
            assertEquals(0, actualToken.accessItems.size)
        }

        @Test
        internal fun user_without_groups_and_without_roles_on_registry_scope_all_catalog_without_env() {

            logCurrentTestMethodName()

            mapper.catalogAudience.clear()

            val expectedScope = SCOPE_REGISTRY_CATALOG_ALL
            given(clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM)).willReturn(expectedScope)
            assertEquals(expectedScope, clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM))

            val actualToken = transformDockerResponseToken()
            assertEquals(0, actualToken.accessItems.size)
        }

        @Test
        internal fun user_without_groups_and_without_roles_on_repository_scope_all_with_namespace() {

            logCurrentTestMethodName()

            val expectedScope = SCOPE_REPO_NAMESPACE_ALL
            given(clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM)).willReturn(expectedScope)
            assertEquals(expectedScope, clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM))

            val actualToken = transformDockerResponseToken()
            assertEquals(0, actualToken.accessItems.size)
        }

        @Test
        internal fun user_without_groups_and_without_roles_on_repository_scope_all_without_namespace() {

            logCurrentTestMethodName()

            val expectedScope = SCOPE_REPO_ALL
            given(clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM)).willReturn(expectedScope)
            assertEquals(expectedScope, clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM))

            val actualToken = transformDockerResponseToken()
            assertEquals(0, actualToken.accessItems.size)
        }

        @Test
        internal fun user_without_groups_and_without_roles_on_repository_scope_pull_with_namespace() {

            logCurrentTestMethodName()

            val expectedScope = SCOPE_REPO_NAMESPACE_PULL
            given(clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM)).willReturn(expectedScope)
            assertEquals(expectedScope, clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM))

            val actualToken = transformDockerResponseToken()
            assertEquals(0, actualToken.accessItems.size)
        }

        @Test
        internal fun user_without_groups_and_without_roles_on_repository_scope_pull_without_namespace() {

            logCurrentTestMethodName()

            val expectedScope = SCOPE_REPO_PULL
            given(clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM)).willReturn(expectedScope)
            assertEquals(expectedScope, clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM))

            val actualToken = transformDockerResponseToken()
            assertEquals(0, actualToken.accessItems.size)
        }

        @Test
        internal fun user_without_groups_and_without_roles_on_repository_scope_push_with_namespace() {

            logCurrentTestMethodName()

            val expectedScope = SCOPE_REPO_NAMESPACE_PUSH
            given(clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM)).willReturn(expectedScope)
            assertEquals(expectedScope, clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM))

            val actualToken = transformDockerResponseToken()
            assertEquals(0, actualToken.accessItems.size)
        }

        @Test
        internal fun user_without_groups_and_without_roles_on_repository_scope_push_without_namespace() {

            logCurrentTestMethodName()

            val expectedScope = SCOPE_REPO_PUSH
            given(clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM)).willReturn(expectedScope)
            assertEquals(expectedScope, clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM))

            val actualToken = transformDockerResponseToken()
            assertEquals(0, actualToken.accessItems.size)
        }

        @Test
        internal fun user_without_groups_and_without_roles_on_repository_scope_pull_and_push_with_namespace() {

            logCurrentTestMethodName()

            val expectedScope = SCOPE_REPO_NAMESPACE_PULL_PUSH
            given(clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM)).willReturn(expectedScope)
            assertEquals(expectedScope, clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM))

            val actualToken = transformDockerResponseToken()
            assertEquals(0, actualToken.accessItems.size)
        }

        @Test
        internal fun user_without_groups_and_without_roles_on_repository_scope_pull_and_push_without_namespace() {

            logCurrentTestMethodName()

            val expectedScope = SCOPE_REPO_PULL_PUSH
            given(clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM)).willReturn(expectedScope)
            assertEquals(expectedScope, clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM))

            val actualToken = transformDockerResponseToken()
            assertEquals(0, actualToken.accessItems.size)
        }

        @Test
        internal fun user_without_groups_and_without_roles_on_repository_plugin_scope_all_with_namespace() {

            logCurrentTestMethodName()

            val expectedScope = SCOPE_REPO_PLUGIN_ALL
            given(clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM)).willReturn(expectedScope)
            assertEquals(expectedScope, clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM))

            val actualToken = transformDockerResponseToken()
            assertEquals(0, actualToken.accessItems.size)
        }

        @Test
        internal fun user_without_groups_and_without_roles_on_repository_plugin_scope_all_without_namespace() {

            logCurrentTestMethodName()

            val expectedScope = SCOPE_REPO_PLUGIN_NAMESPACE_ALL
            given(clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM)).willReturn(expectedScope)
            assertEquals(expectedScope, clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM))

            val actualToken = transformDockerResponseToken()
            assertEquals(0, actualToken.accessItems.size)
        }

        @Test
        internal fun user_without_groups_and_without_roles_on_repository_plugin_scope_pull_with_namespace() {

            logCurrentTestMethodName()

            val expectedScope = SCOPE_REPO_PLUGIN_PULL
            given(clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM)).willReturn(expectedScope)
            assertEquals(expectedScope, clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM))

            val actualToken = transformDockerResponseToken()
            assertEquals(0, actualToken.accessItems.size)
        }

        @Test
        internal fun user_without_groups_and_without_roles_on_repository_plugin_scope_pull_without_namespace() {

            logCurrentTestMethodName()

            val expectedScope = SCOPE_REPO_PLUGIN_NAMESPACE_PULL
            given(clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM)).willReturn(expectedScope)
            assertEquals(expectedScope, clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM))

            val actualToken = transformDockerResponseToken()
            assertEquals(0, actualToken.accessItems.size)
        }

        @Test
        internal fun user_without_groups_and_without_roles_on_repository_plugin_scope_push_with_namespace() {

            logCurrentTestMethodName()

            val expectedScope = SCOPE_REPO_PLUGIN_PUSH
            given(clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM)).willReturn(expectedScope)
            assertEquals(expectedScope, clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM))

            val actualToken = transformDockerResponseToken()
            assertEquals(0, actualToken.accessItems.size)
        }

        @Test
        internal fun user_without_groups_and_without_roles_on_repository_plugin_scope_push_without_namespace() {

            logCurrentTestMethodName()

            val expectedScope = SCOPE_REPO_PLUGIN_NAMESPACE_PUSH
            given(clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM)).willReturn(expectedScope)
            assertEquals(expectedScope, clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM))

            val actualToken = transformDockerResponseToken()
            assertEquals(0, actualToken.accessItems.size)
        }

        @Test
        internal fun user_without_groups_and_without_roles_on_repository_plugin_scope_pull_and_push_with_namespace() {

            logCurrentTestMethodName()

            val expectedScope = SCOPE_REPO_PLUGIN_PULL_PUSH
            given(clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM)).willReturn(expectedScope)
            assertEquals(expectedScope, clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM))

            val actualToken = transformDockerResponseToken()
            assertEquals(0, actualToken.accessItems.size)
        }

        @Test
        internal fun user_without_groups_and_without_roles_on_repository_plugin_scope_pull_and_push_without_namespace() {

            logCurrentTestMethodName()

            val expectedScope = SCOPE_REPO_PLUGIN_NAMESPACE_PULL_PUSH
            given(clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM)).willReturn(expectedScope)
            assertEquals(expectedScope, clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM))

            val actualToken = transformDockerResponseToken()
            assertEquals(0, actualToken.accessItems.size)
        }

        @Test
        internal fun user_with_other_namespace_group_and_without_roles_on_repository_scope_all_with_namespace() {

            logCurrentTestMethodName()

            val expectedScope = SCOPE_REPO_NAMESPACE_ALL
            given(clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM)).willReturn(expectedScope)
            assertEquals(expectedScope, clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM))

            val groups = TestUtils.createGroupsByNames(GROUP_NAMESPACE_OTHER)
            given(userModel.groupsStream).willAnswer { groups.stream() }
            assertEquals(groups, userModel.groupsStream.toList())

            val actualToken = transformDockerResponseToken()
            assertEquals(0, actualToken.accessItems.size)
        }

        @Test
        internal fun user_with_other_namespace_group_and_without_roles_on_repository_scope_all_without_namespace() {

            logCurrentTestMethodName()

            val expectedScope = SCOPE_REPO_ALL
            given(clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM)).willReturn(expectedScope)
            assertEquals(expectedScope, clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM))

            val groups = TestUtils.createGroupsByNames(GROUP_NAMESPACE_OTHER)
            given(userModel.groupsStream).willAnswer { groups.stream() }
            assertEquals(groups, userModel.groupsStream.toList())

            val actualToken = transformDockerResponseToken()
            assertEquals(0, actualToken.accessItems.size)
        }

        @Test
        internal fun user_with_other_namespace_group_and_without_roles_on_repository_scope_pull_with_namespace() {

            logCurrentTestMethodName()

            val expectedScope = SCOPE_REPO_NAMESPACE_PULL
            given(clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM)).willReturn(expectedScope)
            assertEquals(expectedScope, clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM))

            val groups = TestUtils.createGroupsByNames(GROUP_NAMESPACE_OTHER)
            given(userModel.groupsStream).willAnswer { groups.stream() }
            assertEquals(groups, userModel.groupsStream.toList())

            val actualToken = transformDockerResponseToken()
            assertEquals(0, actualToken.accessItems.size)
        }

        @Test
        internal fun user_with_other_namespace_group_and_without_roles_on_repository_scope_pull_without_namespace() {

            logCurrentTestMethodName()

            val expectedScope = SCOPE_REPO_PULL
            given(clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM)).willReturn(expectedScope)
            assertEquals(expectedScope, clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM))

            val groups = TestUtils.createGroupsByNames(GROUP_NAMESPACE_OTHER)
            given(userModel.groupsStream).willAnswer { groups.stream() }
            assertEquals(groups, userModel.groupsStream.toList())

            val actualToken = transformDockerResponseToken()
            assertEquals(0, actualToken.accessItems.size)
        }

        @Test
        internal fun user_with_other_namespace_group_and_without_roles_on_repository_scope_push_with_namespace() {

            logCurrentTestMethodName()

            val expectedScope = SCOPE_REPO_NAMESPACE_PUSH
            given(clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM)).willReturn(expectedScope)
            assertEquals(expectedScope, clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM))

            val groups = TestUtils.createGroupsByNames(GROUP_NAMESPACE_OTHER)
            given(userModel.groupsStream).willAnswer { groups.stream() }
            assertEquals(groups, userModel.groupsStream.toList())

            val actualToken = transformDockerResponseToken()
            assertEquals(0, actualToken.accessItems.size)
        }

        @Test
        internal fun user_with_other_namespace_group_and_without_roles_on_repository_scope_push_without_namespace() {

            logCurrentTestMethodName()

            val expectedScope = SCOPE_REPO_PUSH
            given(clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM)).willReturn(expectedScope)
            assertEquals(expectedScope, clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM))

            val groups = TestUtils.createGroupsByNames(GROUP_NAMESPACE_OTHER)
            given(userModel.groupsStream).willAnswer { groups.stream() }
            assertEquals(groups, userModel.groupsStream.toList())

            val actualToken = transformDockerResponseToken()
            assertEquals(0, actualToken.accessItems.size)
        }

        @Test
        internal fun user_with_other_namespace_group_and_without_roles_on_repository_scope_pull_and_push_with_namespace() {

            logCurrentTestMethodName()

            val expectedScope = SCOPE_REPO_NAMESPACE_PULL_PUSH
            given(clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM)).willReturn(expectedScope)
            assertEquals(expectedScope, clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM))

            val groups = TestUtils.createGroupsByNames(GROUP_NAMESPACE_OTHER)
            given(userModel.groupsStream).willAnswer { groups.stream() }
            assertEquals(groups, userModel.groupsStream.toList())

            val actualToken = transformDockerResponseToken()
            assertEquals(0, actualToken.accessItems.size)
        }

        @Test
        internal fun user_with_other_namespace_group_and_without_roles_on_repository_scope_pull_and_push_without_namespace() {

            logCurrentTestMethodName()

            val expectedScope = SCOPE_REPO_PULL_PUSH
            given(clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM)).willReturn(expectedScope)
            assertEquals(expectedScope, clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM))

            val groups = TestUtils.createGroupsByNames(GROUP_NAMESPACE_OTHER)
            given(userModel.groupsStream).willAnswer { groups.stream() }
            assertEquals(groups, userModel.groupsStream.toList())

            val actualToken = transformDockerResponseToken()
            assertEquals(0, actualToken.accessItems.size)
        }

        @Test
        internal fun user_without_groups_and_with_editor_role_on_registry_scope_all_catalog_with_env_user() {

            logCurrentTestMethodName()

            mapper.catalogAudience.add(ROLE_USER)

            val expectedScope = SCOPE_REGISTRY_CATALOG_ALL
            given(clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM)).willReturn(expectedScope)
            assertEquals(expectedScope, clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM))

            val roles = TestUtils.createClientRolesByNames(ROLE_EDITOR)
            given(userModel.getClientRoleMappingsStream(clientModel)).willAnswer { roles.stream() }

            val actualToken = transformDockerResponseToken()
            assertEquals(1, actualToken.accessItems.size)

            val expectedActions = setOf(ACTION_ALL)
            TestUtils.assertSameContent(expectedActions, actualToken.accessItems.first().actions)
        }

        @Test
        internal fun user_without_groups_and_with_editor_role_on_registry_scope_all_catalog_with_env_editor() {

            logCurrentTestMethodName()

            mapper.catalogAudience.add(ROLE_EDITOR)

            val expectedScope = SCOPE_REGISTRY_CATALOG_ALL
            given(clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM)).willReturn(expectedScope)
            assertEquals(expectedScope, clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM))

            val roles = TestUtils.createClientRolesByNames(ROLE_EDITOR)
            given(userModel.getClientRoleMappingsStream(clientModel)).willAnswer { roles.stream() }

            val actualToken = transformDockerResponseToken()
            assertEquals(1, actualToken.accessItems.size)

            val expectedActions = setOf(ACTION_ALL)
            TestUtils.assertSameContent(expectedActions, actualToken.accessItems.first().actions)
        }

        @Test
        internal fun user_with_namespace_group_and_with_editor_role_on_repository_scope_all_with_namespace() {

            logCurrentTestMethodName()

            val expectedScope = SCOPE_REPO_NAMESPACE_ALL
            given(clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM)).willReturn(expectedScope)
            assertEquals(expectedScope, clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM))

            val groups = TestUtils.createGroupsByNames(GROUP_NAMESPACE)
            given(userModel.groupsStream).willAnswer { groups.stream() }
            assertEquals(groups, userModel.groupsStream.toList())

            val roles = TestUtils.createClientRolesByNames(ROLE_EDITOR)
            given(userModel.getClientRoleMappingsStream(clientModel)).willAnswer { roles.stream() }

            val actualToken = transformDockerResponseToken()
            assertEquals(1, actualToken.accessItems.size)

            val expectedActions = setOf(ACTION_PULL, ACTION_PUSH, ACTION_DELETE)
            TestUtils.assertSameContent(expectedActions, actualToken.accessItems.first().actions)
        }

        @Test
        internal fun user_with_namespace_group_and_with_editor_role_on_repository_scope_all_without_namespace() {

            logCurrentTestMethodName()

            val expectedScope = SCOPE_REPO_ALL
            given(clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM)).willReturn(expectedScope)
            assertEquals(expectedScope, clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM))

            val groups = TestUtils.createGroupsByNames(GROUP_NAMESPACE)
            given(userModel.groupsStream).willAnswer { groups.stream() }
            assertEquals(groups, userModel.groupsStream.toList())

            val roles = TestUtils.createClientRolesByNames(ROLE_EDITOR)
            given(userModel.getClientRoleMappingsStream(clientModel)).willAnswer { roles.stream() }

            val actualToken = transformDockerResponseToken()
            assertEquals(0, actualToken.accessItems.size)
        }

        @Test
        internal fun user_with_namespace_group_and_with_editor_role_on_repository_scope_pull_with_namespace() {

            logCurrentTestMethodName()

            val expectedScope = SCOPE_REPO_NAMESPACE_PULL
            given(clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM)).willReturn(expectedScope)
            assertEquals(expectedScope, clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM))

            val groups = TestUtils.createGroupsByNames(GROUP_NAMESPACE)
            given(userModel.groupsStream).willAnswer { groups.stream() }
            assertEquals(groups, userModel.groupsStream.toList())

            val roles = TestUtils.createClientRolesByNames(ROLE_EDITOR)
            given(userModel.getClientRoleMappingsStream(clientModel)).willAnswer { roles.stream() }

            val actualToken = transformDockerResponseToken()
            assertEquals(1, actualToken.accessItems.size)

            val expectedActions = setOf(ACTION_PULL)
            TestUtils.assertSameContent(expectedActions, actualToken.accessItems.first().actions)
        }

        @Test
        internal fun user_with_namespace_group_and_with_editor_role_on_repository_scope_pull_without_namespace() {

            logCurrentTestMethodName()

            val expectedScope = SCOPE_REPO_PULL
            given(clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM)).willReturn(expectedScope)
            assertEquals(expectedScope, clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM))

            val groups = TestUtils.createGroupsByNames(GROUP_NAMESPACE)
            given(userModel.groupsStream).willAnswer { groups.stream() }
            assertEquals(groups, userModel.groupsStream.toList())

            val roles = TestUtils.createClientRolesByNames(ROLE_EDITOR)
            given(userModel.getClientRoleMappingsStream(clientModel)).willAnswer { roles.stream() }

            val actualToken = transformDockerResponseToken()
            assertEquals(0, actualToken.accessItems.size)
        }

        @Test
        internal fun user_with_namespace_group_and_with_editor_role_on_repository_scope_push_with_namespace() {

            logCurrentTestMethodName()

            val expectedScope = SCOPE_REPO_NAMESPACE_PUSH
            given(clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM)).willReturn(expectedScope)
            assertEquals(expectedScope, clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM))

            val groups = TestUtils.createGroupsByNames(GROUP_NAMESPACE)
            given(userModel.groupsStream).willAnswer { groups.stream() }
            assertEquals(groups, userModel.groupsStream.toList())

            val roles = TestUtils.createClientRolesByNames(ROLE_EDITOR)
            given(userModel.getClientRoleMappingsStream(clientModel)).willAnswer { roles.stream() }

            val actualToken = transformDockerResponseToken()
            assertEquals(1, actualToken.accessItems.size)

            val expectedActions = setOf(ACTION_PUSH)
            TestUtils.assertSameContent(expectedActions, actualToken.accessItems.first().actions)
        }

        @Test
        internal fun user_with_namespace_group_and_with_editor_role_on_repository_scope_push_without_namespace() {

            logCurrentTestMethodName()

            val expectedScope = SCOPE_REPO_PUSH
            given(clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM)).willReturn(expectedScope)
            assertEquals(expectedScope, clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM))

            val groups = TestUtils.createGroupsByNames(GROUP_NAMESPACE)
            given(userModel.groupsStream).willAnswer { groups.stream() }
            assertEquals(groups, userModel.groupsStream.toList())

            val roles = TestUtils.createClientRolesByNames(ROLE_EDITOR)
            given(userModel.getClientRoleMappingsStream(clientModel)).willAnswer { roles.stream() }

            val actualToken = transformDockerResponseToken()
            assertEquals(0, actualToken.accessItems.size)
        }

        @Test
        internal fun user_with_namespace_group_and_with_editor_role_on_repository_scope_pull_and_push_with_namespace() {

            logCurrentTestMethodName()

            val expectedScope = SCOPE_REPO_NAMESPACE_PULL_PUSH
            given(clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM)).willReturn(expectedScope)
            assertEquals(expectedScope, clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM))

            val groups = TestUtils.createGroupsByNames(GROUP_NAMESPACE)
            given(userModel.groupsStream).willAnswer { groups.stream() }
            assertEquals(groups, userModel.groupsStream.toList())

            val roles = TestUtils.createClientRolesByNames(ROLE_EDITOR)
            given(userModel.getClientRoleMappingsStream(clientModel)).willAnswer { roles.stream() }

            val actualToken = transformDockerResponseToken()
            assertEquals(1, actualToken.accessItems.size)

            val expectedActions = setOf(ACTION_PUSH, ACTION_PULL)
            TestUtils.assertSameContent(expectedActions, actualToken.accessItems.first().actions)
        }

        @Test
        internal fun user_with_namespace_group_and_with_editor_role_on_repository_scope_pull_and_push_without_namespace() {

            logCurrentTestMethodName()

            val expectedScope = SCOPE_REPO_PULL_PUSH
            given(clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM)).willReturn(expectedScope)
            assertEquals(expectedScope, clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM))

            val groups = TestUtils.createGroupsByNames(GROUP_NAMESPACE)
            given(userModel.groupsStream).willAnswer { groups.stream() }
            assertEquals(groups, userModel.groupsStream.toList())

            val roles = TestUtils.createClientRolesByNames(ROLE_EDITOR)
            given(userModel.getClientRoleMappingsStream(clientModel)).willAnswer { roles.stream() }

            val actualToken = transformDockerResponseToken()
            assertEquals(0, actualToken.accessItems.size)
        }

        @Test
        internal fun user_with_namespace_group_and_with_editor_role_on_repository_plugin_scope_all_with_namespace() {

            logCurrentTestMethodName()

            val expectedScope = SCOPE_REPO_PLUGIN_NAMESPACE_ALL
            given(clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM)).willReturn(expectedScope)
            assertEquals(expectedScope, clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM))

            val groups = TestUtils.createGroupsByNames(GROUP_NAMESPACE)
            given(userModel.groupsStream).willAnswer { groups.stream() }
            assertEquals(groups, userModel.groupsStream.toList())

            val roles = TestUtils.createClientRolesByNames(ROLE_EDITOR)
            given(userModel.getClientRoleMappingsStream(clientModel)).willAnswer { roles.stream() }

            val actualToken = transformDockerResponseToken()
            assertEquals(1, actualToken.accessItems.size)

            val expectedActions = setOf(ACTION_PULL, ACTION_PUSH, ACTION_DELETE)
            TestUtils.assertSameContent(expectedActions, actualToken.accessItems.first().actions)
        }

        @Test
        internal fun user_with_namespace_group_and_with_editor_role_on_repository_plugin_scope_all_without_namespace() {

            logCurrentTestMethodName()

            val expectedScope = SCOPE_REPO_PLUGIN_ALL
            given(clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM)).willReturn(expectedScope)
            assertEquals(expectedScope, clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM))

            val groups = TestUtils.createGroupsByNames(GROUP_NAMESPACE)
            given(userModel.groupsStream).willAnswer { groups.stream() }
            assertEquals(groups, userModel.groupsStream.toList())

            val roles = TestUtils.createClientRolesByNames(ROLE_EDITOR)
            given(userModel.getClientRoleMappingsStream(clientModel)).willAnswer { roles.stream() }

            val actualToken = transformDockerResponseToken()
            assertEquals(0, actualToken.accessItems.size)
        }

        @Test
        internal fun user_with_namespace_group_and_with_editor_role_on_repository_plugin_scope_pull_with_namespace() {

            logCurrentTestMethodName()

            val expectedScope = SCOPE_REPO_PLUGIN_NAMESPACE_PULL
            given(clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM)).willReturn(expectedScope)
            assertEquals(expectedScope, clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM))

            val groups = TestUtils.createGroupsByNames(GROUP_NAMESPACE)
            given(userModel.groupsStream).willAnswer { groups.stream() }
            assertEquals(groups, userModel.groupsStream.toList())

            val roles = TestUtils.createClientRolesByNames(ROLE_EDITOR)
            given(userModel.getClientRoleMappingsStream(clientModel)).willAnswer { roles.stream() }

            val actualToken = transformDockerResponseToken()
            assertEquals(1, actualToken.accessItems.size)

            val expectedActions = setOf(ACTION_PULL)
            TestUtils.assertSameContent(expectedActions, actualToken.accessItems.first().actions)
        }

        @Test
        internal fun user_with_namespace_group_and_with_editor_role_on_repository_plugin_scope_pull_without_namespace() {

            logCurrentTestMethodName()

            val expectedScope = SCOPE_REPO_PLUGIN_PULL
            given(clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM)).willReturn(expectedScope)
            assertEquals(expectedScope, clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM))

            val groups = TestUtils.createGroupsByNames(GROUP_NAMESPACE)
            given(userModel.groupsStream).willAnswer { groups.stream() }
            assertEquals(groups, userModel.groupsStream.toList())

            val roles = TestUtils.createClientRolesByNames(ROLE_EDITOR)
            given(userModel.getClientRoleMappingsStream(clientModel)).willAnswer { roles.stream() }

            val actualToken = transformDockerResponseToken()
            assertEquals(0, actualToken.accessItems.size)
        }

        @Test
        internal fun user_with_namespace_group_and_with_editor_role_on_repository_plugin_scope_push_with_namespace() {

            logCurrentTestMethodName()

            val expectedScope = SCOPE_REPO_PLUGIN_NAMESPACE_PUSH
            given(clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM)).willReturn(expectedScope)
            assertEquals(expectedScope, clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM))

            val groups = TestUtils.createGroupsByNames(GROUP_NAMESPACE)
            given(userModel.groupsStream).willAnswer { groups.stream() }
            assertEquals(groups, userModel.groupsStream.toList())

            val roles = TestUtils.createClientRolesByNames(ROLE_EDITOR)
            given(userModel.getClientRoleMappingsStream(clientModel)).willAnswer { roles.stream() }

            val actualToken = transformDockerResponseToken()
            assertEquals(1, actualToken.accessItems.size)

            val expectedActions = setOf(ACTION_PUSH)
            TestUtils.assertSameContent(expectedActions, actualToken.accessItems.first().actions)
        }

        @Test
        internal fun user_with_namespace_group_and_with_editor_role_on_repository_plugin_scope_push_without_namespace() {

            logCurrentTestMethodName()

            val expectedScope = SCOPE_REPO_PLUGIN_PUSH
            given(clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM)).willReturn(expectedScope)
            assertEquals(expectedScope, clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM))

            val groups = TestUtils.createGroupsByNames(GROUP_NAMESPACE)
            given(userModel.groupsStream).willAnswer { groups.stream() }
            assertEquals(groups, userModel.groupsStream.toList())

            val roles = TestUtils.createClientRolesByNames(ROLE_EDITOR)
            given(userModel.getClientRoleMappingsStream(clientModel)).willAnswer { roles.stream() }

            val actualToken = transformDockerResponseToken()
            assertEquals(0, actualToken.accessItems.size)
        }

        @Test
        internal fun user_with_namespace_group_and_with_editor_role_on_repository_plugin_scope_pull_and_push_with_namespace() {

            logCurrentTestMethodName()

            val expectedScope = SCOPE_REPO_PLUGIN_NAMESPACE_PULL_PUSH
            given(clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM)).willReturn(expectedScope)
            assertEquals(expectedScope, clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM))

            val groups = TestUtils.createGroupsByNames(GROUP_NAMESPACE)
            given(userModel.groupsStream).willAnswer { groups.stream() }
            assertEquals(groups, userModel.groupsStream.toList())

            val roles = TestUtils.createClientRolesByNames(ROLE_EDITOR)
            given(userModel.getClientRoleMappingsStream(clientModel)).willAnswer { roles.stream() }

            val actualToken = transformDockerResponseToken()
            assertEquals(1, actualToken.accessItems.size)

            val expectedActions = setOf(ACTION_PUSH, ACTION_PULL)
            TestUtils.assertSameContent(expectedActions, actualToken.accessItems.first().actions)
        }

        @Test
        internal fun user_with_namespace_group_and_with_editor_role_on_repository_plugin_scope_pull_and_push_without_namespace() {

            logCurrentTestMethodName()

            val expectedScope = SCOPE_REPO_PLUGIN_PULL_PUSH
            given(clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM)).willReturn(expectedScope)
            assertEquals(expectedScope, clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM))

            val groups = TestUtils.createGroupsByNames(GROUP_NAMESPACE)
            given(userModel.groupsStream).willAnswer { groups.stream() }
            assertEquals(groups, userModel.groupsStream.toList())

            val roles = TestUtils.createClientRolesByNames(ROLE_EDITOR)
            given(userModel.getClientRoleMappingsStream(clientModel)).willAnswer { roles.stream() }

            val actualToken = transformDockerResponseToken()
            assertEquals(0, actualToken.accessItems.size)
        }
    }

    @Nested
    inner class AdminTests {

        @Test
        internal fun user_without_groups_and_with_admin_role_on_registry_scope_all_catalog() {

            logCurrentTestMethodName()

            val expectedScope = SCOPE_REGISTRY_CATALOG_ALL
            given(clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM)).willReturn(expectedScope)
            assertEquals(expectedScope, clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM))

            val roles = TestUtils.createClientRolesByNames(ROLE_ADMIN)
            given(userModel.getClientRoleMappingsStream(clientModel)).willAnswer { roles.stream() }

            val actualToken = transformDockerResponseToken()
            assertEquals(1, actualToken.accessItems.size)

            val expectedActions = setOf(ACTION_ALL)
            TestUtils.assertSameContent(expectedActions, actualToken.accessItems.first().actions)
        }

        @Test
        internal fun user_without_groups_and_with_admin_role_on_repository_scope_all_with_namespace() {

            logCurrentTestMethodName()

            val expectedScope = SCOPE_REPO_NAMESPACE_ALL
            given(clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM)).willReturn(expectedScope)
            assertEquals(expectedScope, clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM))

            val roles = TestUtils.createClientRolesByNames(ROLE_ADMIN)
            given(userModel.getClientRoleMappingsStream(clientModel)).willAnswer { roles.stream() }

            val actualToken = transformDockerResponseToken()
            assertEquals(1, actualToken.accessItems.size)

            val expectedActions = setOf(ACTION_ALL)
            TestUtils.assertSameContent(expectedActions, actualToken.accessItems.first().actions)
        }

        @Test
        internal fun user_without_groups_and_with_admin_role_on_repository_scope_all_without_namespace() {

            logCurrentTestMethodName()

            val expectedScope = SCOPE_REPO_ALL
            given(clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM)).willReturn(expectedScope)
            assertEquals(expectedScope, clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM))

            val roles = TestUtils.createClientRolesByNames(ROLE_ADMIN)
            given(userModel.getClientRoleMappingsStream(clientModel)).willAnswer { roles.stream() }

            val actualToken = transformDockerResponseToken()
            assertEquals(1, actualToken.accessItems.size)

            val expectedActions = setOf(ACTION_ALL)
            TestUtils.assertSameContent(expectedActions, actualToken.accessItems.first().actions)
        }

        @Test
        internal fun user_without_groups_and_with_admin_role_on_repository_scope_pull_with_namespace() {

            logCurrentTestMethodName()

            val expectedScope = SCOPE_REPO_NAMESPACE_PULL
            given(clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM)).willReturn(expectedScope)
            assertEquals(expectedScope, clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM))

            val roles = TestUtils.createClientRolesByNames(ROLE_ADMIN)
            given(userModel.getClientRoleMappingsStream(clientModel)).willAnswer { roles.stream() }

            val actualToken = transformDockerResponseToken()
            assertEquals(1, actualToken.accessItems.size)

            val expectedActions = setOf(ACTION_PULL)
            TestUtils.assertSameContent(expectedActions, actualToken.accessItems.first().actions)
        }

        @Test
        internal fun user_without_groups_and_with_admin_role_on_repository_scope_pull_without_namespace() {

            logCurrentTestMethodName()

            val expectedScope = SCOPE_REPO_PULL
            given(clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM)).willReturn(expectedScope)
            assertEquals(expectedScope, clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM))

            val roles = TestUtils.createClientRolesByNames(ROLE_ADMIN)
            given(userModel.getClientRoleMappingsStream(clientModel)).willAnswer { roles.stream() }

            val actualToken = transformDockerResponseToken()
            assertEquals(1, actualToken.accessItems.size)

            val expectedActions = setOf(ACTION_PULL)
            TestUtils.assertSameContent(expectedActions, actualToken.accessItems.first().actions)
        }

        @Test
        internal fun user_without_groups_and_with_admin_role_on_repository_scope_push_with_namespace() {

            logCurrentTestMethodName()

            val expectedScope = SCOPE_REPO_NAMESPACE_PUSH
            given(clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM)).willReturn(expectedScope)
            assertEquals(expectedScope, clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM))

            val roles = TestUtils.createClientRolesByNames(ROLE_ADMIN)
            given(userModel.getClientRoleMappingsStream(clientModel)).willAnswer { roles.stream() }

            val actualToken = transformDockerResponseToken()
            assertEquals(1, actualToken.accessItems.size)

            val expectedActions = setOf(ACTION_PUSH)
            TestUtils.assertSameContent(expectedActions, actualToken.accessItems.first().actions)
        }

        @Test
        internal fun user_without_groups_and_with_admin_role_on_repository_scope_push_without_namespace() {

            logCurrentTestMethodName()

            val expectedScope = SCOPE_REPO_PUSH
            given(clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM)).willReturn(expectedScope)
            assertEquals(expectedScope, clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM))

            val roles = TestUtils.createClientRolesByNames(ROLE_ADMIN)
            given(userModel.getClientRoleMappingsStream(clientModel)).willAnswer { roles.stream() }

            val actualToken = transformDockerResponseToken()
            assertEquals(1, actualToken.accessItems.size)

            val expectedActions = setOf(ACTION_PUSH)
            TestUtils.assertSameContent(expectedActions, actualToken.accessItems.first().actions)
        }

        @Test
        internal fun user_without_groups_and_with_admin_role_on_repository_scope_pull_and_push_with_namespace() {

            logCurrentTestMethodName()

            val expectedScope = SCOPE_REPO_NAMESPACE_PULL_PUSH
            given(clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM)).willReturn(expectedScope)
            assertEquals(expectedScope, clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM))

            val roles = TestUtils.createClientRolesByNames(ROLE_ADMIN)
            given(userModel.getClientRoleMappingsStream(clientModel)).willAnswer { roles.stream() }

            val actualToken = transformDockerResponseToken()
            assertEquals(1, actualToken.accessItems.size)

            val expectedActions = setOf(ACTION_PUSH, ACTION_PULL)
            TestUtils.assertSameContent(expectedActions, actualToken.accessItems.first().actions)
        }

        @Test
        internal fun user_without_groups_and_with_admin_role_on_repository_scope_pull_and_push_without_namespace() {

            logCurrentTestMethodName()

            val expectedScope = SCOPE_REPO_PULL_PUSH
            given(clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM)).willReturn(expectedScope)
            assertEquals(expectedScope, clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM))

            val roles = TestUtils.createClientRolesByNames(ROLE_ADMIN)
            given(userModel.getClientRoleMappingsStream(clientModel)).willAnswer { roles.stream() }

            val actualToken = transformDockerResponseToken()
            assertEquals(1, actualToken.accessItems.size)

            val expectedActions = setOf(ACTION_PUSH, ACTION_PULL)
            TestUtils.assertSameContent(expectedActions, actualToken.accessItems.first().actions)
        }

        @Test
        internal fun user_without_groups_and_with_admin_role_on_repository_plugin_scope_all_with_namespace() {

            logCurrentTestMethodName()

            val expectedScope = SCOPE_REPO_PLUGIN_NAMESPACE_ALL
            given(clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM)).willReturn(expectedScope)
            assertEquals(expectedScope, clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM))

            val roles = TestUtils.createClientRolesByNames(ROLE_ADMIN)
            given(userModel.getClientRoleMappingsStream(clientModel)).willAnswer { roles.stream() }

            val actualToken = transformDockerResponseToken()
            assertEquals(1, actualToken.accessItems.size)

            val expectedActions = setOf(ACTION_ALL)
            TestUtils.assertSameContent(expectedActions, actualToken.accessItems.first().actions)
        }

        @Test
        internal fun user_without_groups_and_with_admin_role_on_repository_plugin_scope_all_without_namespace() {

            logCurrentTestMethodName()

            val expectedScope = SCOPE_REPO_PLUGIN_ALL
            given(clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM)).willReturn(expectedScope)
            assertEquals(expectedScope, clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM))

            val roles = TestUtils.createClientRolesByNames(ROLE_ADMIN)
            given(userModel.getClientRoleMappingsStream(clientModel)).willAnswer { roles.stream() }

            val actualToken = transformDockerResponseToken()
            assertEquals(1, actualToken.accessItems.size)

            val expectedActions = setOf(ACTION_ALL)
            TestUtils.assertSameContent(expectedActions, actualToken.accessItems.first().actions)
        }

        @Test
        internal fun user_without_groups_and_with_admin_role_on_repository_plugin_scope_pull_with_namespace() {

            logCurrentTestMethodName()

            val expectedScope = SCOPE_REPO_PLUGIN_NAMESPACE_PULL
            given(clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM)).willReturn(expectedScope)
            assertEquals(expectedScope, clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM))

            val roles = TestUtils.createClientRolesByNames(ROLE_ADMIN)
            given(userModel.getClientRoleMappingsStream(clientModel)).willAnswer { roles.stream() }

            val actualToken = transformDockerResponseToken()
            assertEquals(1, actualToken.accessItems.size)

            val expectedActions = setOf(ACTION_PULL)
            TestUtils.assertSameContent(expectedActions, actualToken.accessItems.first().actions)
        }

        @Test
        internal fun user_without_groups_and_with_admin_role_on_repository_plugin_scope_pull_without_namespace() {

            logCurrentTestMethodName()

            val expectedScope = SCOPE_REPO_PLUGIN_PULL
            given(clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM)).willReturn(expectedScope)
            assertEquals(expectedScope, clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM))

            val roles = TestUtils.createClientRolesByNames(ROLE_ADMIN)
            given(userModel.getClientRoleMappingsStream(clientModel)).willAnswer { roles.stream() }

            val actualToken = transformDockerResponseToken()
            assertEquals(1, actualToken.accessItems.size)

            val expectedActions = setOf(ACTION_PULL)
            TestUtils.assertSameContent(expectedActions, actualToken.accessItems.first().actions)
        }

        @Test
        internal fun user_without_groups_and_with_admin_role_on_repository_plugin_scope_push_with_namespace() {

            logCurrentTestMethodName()

            val expectedScope = SCOPE_REPO_PLUGIN_NAMESPACE_PUSH
            given(clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM)).willReturn(expectedScope)
            assertEquals(expectedScope, clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM))

            val roles = TestUtils.createClientRolesByNames(ROLE_ADMIN)
            given(userModel.getClientRoleMappingsStream(clientModel)).willAnswer { roles.stream() }

            val actualToken = transformDockerResponseToken()
            assertEquals(1, actualToken.accessItems.size)

            val expectedActions = setOf(ACTION_PUSH)
            TestUtils.assertSameContent(expectedActions, actualToken.accessItems.first().actions)
        }

        @Test
        internal fun user_without_groups_and_with_admin_role_on_repository_plugin_scope_push_without_namespace() {

            logCurrentTestMethodName()

            val expectedScope = SCOPE_REPO_PLUGIN_PUSH
            given(clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM)).willReturn(expectedScope)
            assertEquals(expectedScope, clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM))

            val roles = TestUtils.createClientRolesByNames(ROLE_ADMIN)
            given(userModel.getClientRoleMappingsStream(clientModel)).willAnswer { roles.stream() }

            val actualToken = transformDockerResponseToken()
            assertEquals(1, actualToken.accessItems.size)

            val expectedActions = setOf(ACTION_PUSH)
            TestUtils.assertSameContent(expectedActions, actualToken.accessItems.first().actions)
        }

        @Test
        internal fun user_without_groups_and_with_admin_role_on_repository_plugin_scope_pull_and_push_with_namespace() {

            logCurrentTestMethodName()

            val expectedScope = SCOPE_REPO_PLUGIN_NAMESPACE_PULL_PUSH
            given(clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM)).willReturn(expectedScope)
            assertEquals(expectedScope, clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM))

            val roles = TestUtils.createClientRolesByNames(ROLE_ADMIN)
            given(userModel.getClientRoleMappingsStream(clientModel)).willAnswer { roles.stream() }

            val actualToken = transformDockerResponseToken()
            assertEquals(1, actualToken.accessItems.size)

            val expectedActions = setOf(ACTION_PUSH, ACTION_PULL)
            TestUtils.assertSameContent(expectedActions, actualToken.accessItems.first().actions)
        }

        @Test
        internal fun user_without_groups_and_with_admin_role_on_repository_plugin_scope_pull_and_push_without_namespace() {

            logCurrentTestMethodName()

            val expectedScope = SCOPE_REPO_PLUGIN_PULL_PUSH
            given(clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM)).willReturn(expectedScope)
            assertEquals(expectedScope, clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM))

            val roles = TestUtils.createClientRolesByNames(ROLE_ADMIN)
            given(userModel.getClientRoleMappingsStream(clientModel)).willAnswer { roles.stream() }

            val actualToken = transformDockerResponseToken()
            assertEquals(1, actualToken.accessItems.size)

            val expectedActions = setOf(ACTION_PUSH, ACTION_PULL)
            TestUtils.assertSameContent(expectedActions, actualToken.accessItems.first().actions)
        }

        @Test
        internal fun user_with_namespace_group_and_with_admin_role_on_repository_scope_all_with_namespace() {

            logCurrentTestMethodName()

            val expectedScope = SCOPE_REPO_NAMESPACE_ALL
            given(clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM)).willReturn(expectedScope)
            assertEquals(expectedScope, clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM))

            val groups = TestUtils.createGroupsByNames(GROUP_NAMESPACE)
            given(userModel.groupsStream).willAnswer { groups.stream() }
            assertEquals(groups, userModel.groupsStream.toList())

            val roles = TestUtils.createClientRolesByNames(ROLE_ADMIN)
            given(userModel.getClientRoleMappingsStream(clientModel)).willAnswer { roles.stream() }

            val actualToken = transformDockerResponseToken()
            assertEquals(1, actualToken.accessItems.size)

            val expectedActions = setOf(ACTION_ALL)
            TestUtils.assertSameContent(expectedActions, actualToken.accessItems.first().actions)
        }

        @Test
        internal fun user_with_namespace_group_and_with_admin_role_on_repository_scope_all_without_namespace() {

            logCurrentTestMethodName()

            val expectedScope = SCOPE_REPO_ALL
            given(clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM)).willReturn(expectedScope)
            assertEquals(expectedScope, clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM))

            val groups = TestUtils.createGroupsByNames(GROUP_NAMESPACE)
            given(userModel.groupsStream).willAnswer { groups.stream() }
            assertEquals(groups, userModel.groupsStream.toList())

            val roles = TestUtils.createClientRolesByNames(ROLE_ADMIN)
            given(userModel.getClientRoleMappingsStream(clientModel)).willAnswer { roles.stream() }

            val actualToken = transformDockerResponseToken()
            assertEquals(1, actualToken.accessItems.size)

            val expectedActions = setOf(ACTION_ALL)
            TestUtils.assertSameContent(expectedActions, actualToken.accessItems.first().actions)
        }

        @Test
        internal fun user_with_namespace_group_and_with_admin_role_on_repository_scope_push_with_namespace() {

            logCurrentTestMethodName()

            val expectedScope = SCOPE_REPO_NAMESPACE_PUSH
            given(clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM)).willReturn(expectedScope)
            assertEquals(expectedScope, clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM))

            val groups = TestUtils.createGroupsByNames(GROUP_NAMESPACE)
            given(userModel.groupsStream).willAnswer { groups.stream() }
            assertEquals(groups, userModel.groupsStream.toList())

            val roles = TestUtils.createClientRolesByNames(ROLE_ADMIN)
            given(userModel.getClientRoleMappingsStream(clientModel)).willAnswer { roles.stream() }

            val actualToken = transformDockerResponseToken()
            assertEquals(1, actualToken.accessItems.size)

            val expectedActions = setOf(ACTION_PUSH)
            TestUtils.assertSameContent(expectedActions, actualToken.accessItems.first().actions)
        }

        @Test
        internal fun user_with_namespace_group_and_with_admin_role_on_repository_scope_push_without_namespace() {

            logCurrentTestMethodName()

            val expectedScope = SCOPE_REPO_PUSH
            given(clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM)).willReturn(expectedScope)
            assertEquals(expectedScope, clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM))

            val groups = TestUtils.createGroupsByNames(GROUP_NAMESPACE)
            given(userModel.groupsStream).willAnswer { groups.stream() }
            assertEquals(groups, userModel.groupsStream.toList())

            val roles = TestUtils.createClientRolesByNames(ROLE_ADMIN)
            given(userModel.getClientRoleMappingsStream(clientModel)).willAnswer { roles.stream() }

            val actualToken = transformDockerResponseToken()
            assertEquals(1, actualToken.accessItems.size)

            val expectedActions = setOf(ACTION_PUSH)
            TestUtils.assertSameContent(expectedActions, actualToken.accessItems.first().actions)
        }

        @Test
        internal fun user_with_namespace_group_and_with_admin_role_on_repository_scope_pull_with_namespace() {

            logCurrentTestMethodName()

            val expectedScope = SCOPE_REPO_NAMESPACE_PULL
            given(clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM)).willReturn(expectedScope)
            assertEquals(expectedScope, clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM))

            val groups = TestUtils.createGroupsByNames(GROUP_NAMESPACE)
            given(userModel.groupsStream).willAnswer { groups.stream() }
            assertEquals(groups, userModel.groupsStream.toList())

            val roles = TestUtils.createClientRolesByNames(ROLE_ADMIN)
            given(userModel.getClientRoleMappingsStream(clientModel)).willAnswer { roles.stream() }

            val actualToken = transformDockerResponseToken()
            assertEquals(1, actualToken.accessItems.size)

            val expectedActions = setOf(ACTION_PULL)
            TestUtils.assertSameContent(expectedActions, actualToken.accessItems.first().actions)
        }

        @Test
        internal fun user_with_namespace_group_and_with_admin_role_on_repository_scope_pull_without_namespace() {

            logCurrentTestMethodName()

            val expectedScope = SCOPE_REPO_PULL
            given(clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM)).willReturn(expectedScope)
            assertEquals(expectedScope, clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM))

            val groups = TestUtils.createGroupsByNames(GROUP_NAMESPACE)
            given(userModel.groupsStream).willAnswer { groups.stream() }
            assertEquals(groups, userModel.groupsStream.toList())

            val roles = TestUtils.createClientRolesByNames(ROLE_ADMIN)
            given(userModel.getClientRoleMappingsStream(clientModel)).willAnswer { roles.stream() }

            val actualToken = transformDockerResponseToken()
            assertEquals(1, actualToken.accessItems.size)

            val expectedActions = setOf(ACTION_PULL)
            TestUtils.assertSameContent(expectedActions, actualToken.accessItems.first().actions)
        }

        @Test
        internal fun user_with_namespace_group_and_with_admin_role_on_repository_scope_pull_and_push_with_namespace() {

            logCurrentTestMethodName()

            val expectedScope = SCOPE_REPO_NAMESPACE_PULL_PUSH
            given(clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM)).willReturn(expectedScope)
            assertEquals(expectedScope, clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM))

            val groups = TestUtils.createGroupsByNames(GROUP_NAMESPACE)
            given(userModel.groupsStream).willAnswer { groups.stream() }
            assertEquals(groups, userModel.groupsStream.toList())

            val roles = TestUtils.createClientRolesByNames(ROLE_ADMIN)
            given(userModel.getClientRoleMappingsStream(clientModel)).willAnswer { roles.stream() }

            val actualToken = transformDockerResponseToken()
            assertEquals(1, actualToken.accessItems.size)

            val expectedActions = setOf(ACTION_PUSH, ACTION_PULL)
            TestUtils.assertSameContent(expectedActions, actualToken.accessItems.first().actions)
        }

        @Test
        internal fun user_with_namespace_group_and_with_admin_role_on_repository_scope_pull_and_push_without_namespace() {

            logCurrentTestMethodName()

            val expectedScope = SCOPE_REPO_PULL_PUSH
            given(clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM)).willReturn(expectedScope)
            assertEquals(expectedScope, clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM))

            val groups = TestUtils.createGroupsByNames(GROUP_NAMESPACE)
            given(userModel.groupsStream).willAnswer { groups.stream() }
            assertEquals(groups, userModel.groupsStream.toList())

            val roles = TestUtils.createClientRolesByNames(ROLE_ADMIN)
            given(userModel.getClientRoleMappingsStream(clientModel)).willAnswer { roles.stream() }

            val actualToken = transformDockerResponseToken()
            assertEquals(1, actualToken.accessItems.size)

            val expectedActions = setOf(ACTION_PUSH, ACTION_PULL)
            TestUtils.assertSameContent(expectedActions, actualToken.accessItems.first().actions)
        }

        @Test
        internal fun user_with_namespace_group_and_with_admin_role_on_repository_plugin_scope_all_with_namespace() {

            logCurrentTestMethodName()

            val expectedScope = SCOPE_REPO_PLUGIN_NAMESPACE_ALL
            given(clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM)).willReturn(expectedScope)
            assertEquals(expectedScope, clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM))

            val groups = TestUtils.createGroupsByNames(GROUP_NAMESPACE)
            given(userModel.groupsStream).willAnswer { groups.stream() }
            assertEquals(groups, userModel.groupsStream.toList())

            val roles = TestUtils.createClientRolesByNames(ROLE_ADMIN)
            given(userModel.getClientRoleMappingsStream(clientModel)).willAnswer { roles.stream() }

            val actualToken = transformDockerResponseToken()
            assertEquals(1, actualToken.accessItems.size)

            val expectedActions = setOf(ACTION_ALL)
            TestUtils.assertSameContent(expectedActions, actualToken.accessItems.first().actions)
        }

        @Test
        internal fun user_with_namespace_group_and_with_admin_role_on_repository_plugin_scope_all_without_namespace() {

            logCurrentTestMethodName()

            val expectedScope = SCOPE_REPO_PLUGIN_ALL
            given(clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM)).willReturn(expectedScope)
            assertEquals(expectedScope, clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM))

            val groups = TestUtils.createGroupsByNames(GROUP_NAMESPACE)
            given(userModel.groupsStream).willAnswer { groups.stream() }
            assertEquals(groups, userModel.groupsStream.toList())

            val roles = TestUtils.createClientRolesByNames(ROLE_ADMIN)
            given(userModel.getClientRoleMappingsStream(clientModel)).willAnswer { roles.stream() }

            val actualToken = transformDockerResponseToken()
            assertEquals(1, actualToken.accessItems.size)

            val expectedActions = setOf(ACTION_ALL)
            TestUtils.assertSameContent(expectedActions, actualToken.accessItems.first().actions)
        }

        @Test
        internal fun user_with_namespace_group_and_with_admin_role_on_repository_plugin_scope_push_with_namespace() {

            logCurrentTestMethodName()

            val expectedScope = SCOPE_REPO_PLUGIN_NAMESPACE_PUSH
            given(clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM)).willReturn(expectedScope)
            assertEquals(expectedScope, clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM))

            val groups = TestUtils.createGroupsByNames(GROUP_NAMESPACE)
            given(userModel.groupsStream).willAnswer { groups.stream() }
            assertEquals(groups, userModel.groupsStream.toList())

            val roles = TestUtils.createClientRolesByNames(ROLE_ADMIN)
            given(userModel.getClientRoleMappingsStream(clientModel)).willAnswer { roles.stream() }

            val actualToken = transformDockerResponseToken()
            assertEquals(1, actualToken.accessItems.size)

            val expectedActions = setOf(ACTION_PUSH)
            TestUtils.assertSameContent(expectedActions, actualToken.accessItems.first().actions)
        }

        @Test
        internal fun user_with_namespace_group_and_with_admin_role_on_repository_plugin_scope_push_without_namespace() {

            logCurrentTestMethodName()

            val expectedScope = SCOPE_REPO_PLUGIN_PUSH
            given(clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM)).willReturn(expectedScope)
            assertEquals(expectedScope, clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM))

            val groups = TestUtils.createGroupsByNames(GROUP_NAMESPACE)
            given(userModel.groupsStream).willAnswer { groups.stream() }
            assertEquals(groups, userModel.groupsStream.toList())

            val roles = TestUtils.createClientRolesByNames(ROLE_ADMIN)
            given(userModel.getClientRoleMappingsStream(clientModel)).willAnswer { roles.stream() }

            val actualToken = transformDockerResponseToken()
            assertEquals(1, actualToken.accessItems.size)

            val expectedActions = setOf(ACTION_PUSH)
            TestUtils.assertSameContent(expectedActions, actualToken.accessItems.first().actions)
        }

        @Test
        internal fun user_with_namespace_group_and_with_admin_role_on_repository_plugin_scope_pull_with_namespace() {

            logCurrentTestMethodName()

            val expectedScope = SCOPE_REPO_PLUGIN_NAMESPACE_PULL
            given(clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM)).willReturn(expectedScope)
            assertEquals(expectedScope, clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM))

            val groups = TestUtils.createGroupsByNames(GROUP_NAMESPACE)
            given(userModel.groupsStream).willAnswer { groups.stream() }
            assertEquals(groups, userModel.groupsStream.toList())

            val roles = TestUtils.createClientRolesByNames(ROLE_ADMIN)
            given(userModel.getClientRoleMappingsStream(clientModel)).willAnswer { roles.stream() }

            val actualToken = transformDockerResponseToken()
            assertEquals(1, actualToken.accessItems.size)

            val expectedActions = setOf(ACTION_PULL)
            TestUtils.assertSameContent(expectedActions, actualToken.accessItems.first().actions)
        }

        @Test
        internal fun user_with_namespace_group_and_with_admin_role_on_repository_plugin_scope_pull_without_namespace() {

            logCurrentTestMethodName()

            val expectedScope = SCOPE_REPO_PLUGIN_PULL
            given(clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM)).willReturn(expectedScope)
            assertEquals(expectedScope, clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM))

            val groups = TestUtils.createGroupsByNames(GROUP_NAMESPACE)
            given(userModel.groupsStream).willAnswer { groups.stream() }
            assertEquals(groups, userModel.groupsStream.toList())

            val roles = TestUtils.createClientRolesByNames(ROLE_ADMIN)
            given(userModel.getClientRoleMappingsStream(clientModel)).willAnswer { roles.stream() }

            val actualToken = transformDockerResponseToken()
            assertEquals(1, actualToken.accessItems.size)

            val expectedActions = setOf(ACTION_PULL)
            TestUtils.assertSameContent(expectedActions, actualToken.accessItems.first().actions)
        }

        @Test
        internal fun user_with_namespace_group_and_with_admin_role_on_repository_plugin_scope_pull_and_push_with_namespace() {

            logCurrentTestMethodName()

            val expectedScope = SCOPE_REPO_PLUGIN_NAMESPACE_PULL_PUSH
            given(clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM)).willReturn(expectedScope)
            assertEquals(expectedScope, clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM))

            val groups = TestUtils.createGroupsByNames(GROUP_NAMESPACE)
            given(userModel.groupsStream).willAnswer { groups.stream() }
            assertEquals(groups, userModel.groupsStream.toList())

            val roles = TestUtils.createClientRolesByNames(ROLE_ADMIN)
            given(userModel.getClientRoleMappingsStream(clientModel)).willAnswer { roles.stream() }

            val actualToken = transformDockerResponseToken()
            assertEquals(1, actualToken.accessItems.size)

            val expectedActions = setOf(ACTION_PUSH, ACTION_PULL)
            TestUtils.assertSameContent(expectedActions, actualToken.accessItems.first().actions)
        }

        @Test
        internal fun user_with_namespace_group_and_with_admin_role_on_repository_plugin_scope_pull_and_push_without_namespace() {

            logCurrentTestMethodName()

            val expectedScope = SCOPE_REPO_PLUGIN_PULL_PUSH
            given(clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM)).willReturn(expectedScope)
            assertEquals(expectedScope, clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM))

            val groups = TestUtils.createGroupsByNames(GROUP_NAMESPACE)
            given(userModel.groupsStream).willAnswer { groups.stream() }
            assertEquals(groups, userModel.groupsStream.toList())

            val roles = TestUtils.createClientRolesByNames(ROLE_ADMIN)
            given(userModel.getClientRoleMappingsStream(clientModel)).willAnswer { roles.stream() }

            val actualToken = transformDockerResponseToken()
            assertEquals(1, actualToken.accessItems.size)

            val expectedActions = setOf(ACTION_PUSH, ACTION_PULL)
            TestUtils.assertSameContent(expectedActions, actualToken.accessItems.first().actions)
        }

        @Test
        internal fun user_with_other_namespace_group_and_with_admin_role_on_repository_scope_all_with_namespace() {

            logCurrentTestMethodName()

            val expectedScope = SCOPE_REPO_NAMESPACE_ALL
            given(clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM)).willReturn(expectedScope)
            assertEquals(expectedScope, clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM))

            val groups = TestUtils.createGroupsByNames(GROUP_NAMESPACE_OTHER)
            given(userModel.groupsStream).willAnswer { groups.stream() }
            assertEquals(groups, userModel.groupsStream.toList())

            val roles = TestUtils.createClientRolesByNames(ROLE_ADMIN)
            given(userModel.getClientRoleMappingsStream(clientModel)).willAnswer { roles.stream() }

            val actualToken = transformDockerResponseToken()
            assertEquals(1, actualToken.accessItems.size)

            val expectedActions = setOf(ACTION_ALL)
            TestUtils.assertSameContent(expectedActions, actualToken.accessItems.first().actions)
        }

        @Test
        internal fun user_with_other_namespace_group_and_with_admin_role_on_repository_scope_all_without_namespace() {

            logCurrentTestMethodName()

            val expectedScope = SCOPE_REPO_ALL
            given(clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM)).willReturn(expectedScope)
            assertEquals(expectedScope, clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM))

            val groups = TestUtils.createGroupsByNames(GROUP_NAMESPACE_OTHER)
            given(userModel.groupsStream).willAnswer { groups.stream() }
            assertEquals(groups, userModel.groupsStream.toList())

            val roles = TestUtils.createClientRolesByNames(ROLE_ADMIN)
            given(userModel.getClientRoleMappingsStream(clientModel)).willAnswer { roles.stream() }

            val actualToken = transformDockerResponseToken()
            assertEquals(1, actualToken.accessItems.size)

            val expectedActions = setOf(ACTION_ALL)
            TestUtils.assertSameContent(expectedActions, actualToken.accessItems.first().actions)
        }

        @Test
        internal fun user_with_other_namespace_group_and_with_admin_role_on_repository_scope_push_with_namespace() {

            logCurrentTestMethodName()

            val expectedScope = SCOPE_REPO_NAMESPACE_PUSH
            given(clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM)).willReturn(expectedScope)
            assertEquals(expectedScope, clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM))

            val groups = TestUtils.createGroupsByNames(GROUP_NAMESPACE_OTHER)
            given(userModel.groupsStream).willAnswer { groups.stream() }
            assertEquals(groups, userModel.groupsStream.toList())

            val roles = TestUtils.createClientRolesByNames(ROLE_ADMIN)
            given(userModel.getClientRoleMappingsStream(clientModel)).willAnswer { roles.stream() }

            val actualToken = transformDockerResponseToken()
            assertEquals(1, actualToken.accessItems.size)

            val expectedActions = setOf(ACTION_PUSH)
            TestUtils.assertSameContent(expectedActions, actualToken.accessItems.first().actions)
        }

        @Test
        internal fun user_with_other_namespace_group_and_with_admin_role_on_repository_scope_push_without_namespace() {

            logCurrentTestMethodName()

            val expectedScope = SCOPE_REPO_PUSH
            given(clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM)).willReturn(expectedScope)
            assertEquals(expectedScope, clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM))

            val groups = TestUtils.createGroupsByNames(GROUP_NAMESPACE_OTHER)
            given(userModel.groupsStream).willAnswer { groups.stream() }
            assertEquals(groups, userModel.groupsStream.toList())

            val roles = TestUtils.createClientRolesByNames(ROLE_ADMIN)
            given(userModel.getClientRoleMappingsStream(clientModel)).willAnswer { roles.stream() }

            val actualToken = transformDockerResponseToken()
            assertEquals(1, actualToken.accessItems.size)

            val expectedActions = setOf(ACTION_PUSH)
            TestUtils.assertSameContent(expectedActions, actualToken.accessItems.first().actions)
        }

        @Test
        internal fun user_with_other_namespace_group_and_with_admin_role_on_repository_scope_pull_with_namespace() {

            logCurrentTestMethodName()

            val expectedScope = SCOPE_REPO_NAMESPACE_PULL
            given(clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM)).willReturn(expectedScope)
            assertEquals(expectedScope, clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM))

            val groups = TestUtils.createGroupsByNames(GROUP_NAMESPACE_OTHER)
            given(userModel.groupsStream).willAnswer { groups.stream() }
            assertEquals(groups, userModel.groupsStream.toList())

            val roles = TestUtils.createClientRolesByNames(ROLE_ADMIN)
            given(userModel.getClientRoleMappingsStream(clientModel)).willAnswer { roles.stream() }

            val actualToken = transformDockerResponseToken()
            assertEquals(1, actualToken.accessItems.size)

            val expectedActions = setOf(ACTION_PULL)
            TestUtils.assertSameContent(expectedActions, actualToken.accessItems.first().actions)
        }

        @Test
        internal fun user_with_other_namespace_group_and_with_admin_role_on_repository_scope_pull_without_namespace() {

            logCurrentTestMethodName()

            val expectedScope = SCOPE_REPO_PULL
            given(clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM)).willReturn(expectedScope)
            assertEquals(expectedScope, clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM))

            val groups = TestUtils.createGroupsByNames(GROUP_NAMESPACE_OTHER)
            given(userModel.groupsStream).willAnswer { groups.stream() }
            assertEquals(groups, userModel.groupsStream.toList())

            val roles = TestUtils.createClientRolesByNames(ROLE_ADMIN)
            given(userModel.getClientRoleMappingsStream(clientModel)).willAnswer { roles.stream() }

            val actualToken = transformDockerResponseToken()
            assertEquals(1, actualToken.accessItems.size)

            val expectedActions = setOf(ACTION_PULL)
            TestUtils.assertSameContent(expectedActions, actualToken.accessItems.first().actions)
        }

        @Test
        internal fun user_with_other_namespace_group_and_with_admin_role_on_repository_scope_pull_and_push_with_namespace() {

            logCurrentTestMethodName()

            val expectedScope = SCOPE_REPO_NAMESPACE_PULL_PUSH
            given(clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM)).willReturn(expectedScope)
            assertEquals(expectedScope, clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM))

            val groups = TestUtils.createGroupsByNames(GROUP_NAMESPACE_OTHER)
            given(userModel.groupsStream).willAnswer { groups.stream() }
            assertEquals(groups, userModel.groupsStream.toList())

            val roles = TestUtils.createClientRolesByNames(ROLE_ADMIN)
            given(userModel.getClientRoleMappingsStream(clientModel)).willAnswer { roles.stream() }

            val actualToken = transformDockerResponseToken()
            assertEquals(1, actualToken.accessItems.size)

            val expectedActions = setOf(ACTION_PUSH, ACTION_PULL)
            TestUtils.assertSameContent(expectedActions, actualToken.accessItems.first().actions)
        }

        @Test
        internal fun user_with_other_namespace_group_and_with_admin_role_on_repository_scope_pull_and_push_without_namespace() {

            logCurrentTestMethodName()

            val expectedScope = SCOPE_REPO_PULL_PUSH
            given(clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM)).willReturn(expectedScope)
            assertEquals(expectedScope, clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM))

            val groups = TestUtils.createGroupsByNames(GROUP_NAMESPACE_OTHER)
            given(userModel.groupsStream).willAnswer { groups.stream() }
            assertEquals(groups, userModel.groupsStream.toList())

            val roles = TestUtils.createClientRolesByNames(ROLE_ADMIN)
            given(userModel.getClientRoleMappingsStream(clientModel)).willAnswer { roles.stream() }

            val actualToken = transformDockerResponseToken()
            assertEquals(1, actualToken.accessItems.size)

            val expectedActions = setOf(ACTION_PUSH, ACTION_PULL)
            TestUtils.assertSameContent(expectedActions, actualToken.accessItems.first().actions)
        }

        @Test
        internal fun user_with_other_namespace_group_and_with_admin_role_on_repository_plugin_scope_all_with_namespace() {

            logCurrentTestMethodName()

            val expectedScope = SCOPE_REPO_PLUGIN_NAMESPACE_ALL
            given(clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM)).willReturn(expectedScope)
            assertEquals(expectedScope, clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM))

            val groups = TestUtils.createGroupsByNames(GROUP_NAMESPACE_OTHER)
            given(userModel.groupsStream).willAnswer { groups.stream() }
            assertEquals(groups, userModel.groupsStream.toList())

            val roles = TestUtils.createClientRolesByNames(ROLE_ADMIN)
            given(userModel.getClientRoleMappingsStream(clientModel)).willAnswer { roles.stream() }

            val actualToken = transformDockerResponseToken()
            assertEquals(1, actualToken.accessItems.size)

            val expectedActions = setOf(ACTION_ALL)
            TestUtils.assertSameContent(expectedActions, actualToken.accessItems.first().actions)
        }

        @Test
        internal fun user_with_other_namespace_group_and_with_admin_role_on_repository_plugin_scope_all_without_namespace() {

            logCurrentTestMethodName()

            val expectedScope = SCOPE_REPO_PLUGIN_ALL
            given(clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM)).willReturn(expectedScope)
            assertEquals(expectedScope, clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM))

            val groups = TestUtils.createGroupsByNames(GROUP_NAMESPACE_OTHER)
            given(userModel.groupsStream).willAnswer { groups.stream() }
            assertEquals(groups, userModel.groupsStream.toList())

            val roles = TestUtils.createClientRolesByNames(ROLE_ADMIN)
            given(userModel.getClientRoleMappingsStream(clientModel)).willAnswer { roles.stream() }

            val actualToken = transformDockerResponseToken()
            assertEquals(1, actualToken.accessItems.size)

            val expectedActions = setOf(ACTION_ALL)
            TestUtils.assertSameContent(expectedActions, actualToken.accessItems.first().actions)
        }

        @Test
        internal fun user_with_other_namespace_group_and_with_admin_role_on_repository_plugin_scope_pull_with_namespace() {

            logCurrentTestMethodName()

            val expectedScope = SCOPE_REPO_PLUGIN_NAMESPACE_PULL
            given(clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM)).willReturn(expectedScope)
            assertEquals(expectedScope, clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM))

            val groups = TestUtils.createGroupsByNames(GROUP_NAMESPACE_OTHER)
            given(userModel.groupsStream).willAnswer { groups.stream() }
            assertEquals(groups, userModel.groupsStream.toList())

            val roles = TestUtils.createClientRolesByNames(ROLE_ADMIN)
            given(userModel.getClientRoleMappingsStream(clientModel)).willAnswer { roles.stream() }

            val actualToken = transformDockerResponseToken()
            assertEquals(1, actualToken.accessItems.size)

            val expectedActions = setOf(ACTION_PULL)
            TestUtils.assertSameContent(expectedActions, actualToken.accessItems.first().actions)
        }

        @Test
        internal fun user_with_other_namespace_group_and_with_admin_role_on_repository_plugin_scope_pull_without_namespace() {

            logCurrentTestMethodName()

            val expectedScope = SCOPE_REPO_PLUGIN_PULL
            given(clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM)).willReturn(expectedScope)
            assertEquals(expectedScope, clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM))

            val groups = TestUtils.createGroupsByNames(GROUP_NAMESPACE_OTHER)
            given(userModel.groupsStream).willAnswer { groups.stream() }
            assertEquals(groups, userModel.groupsStream.toList())

            val roles = TestUtils.createClientRolesByNames(ROLE_ADMIN)
            given(userModel.getClientRoleMappingsStream(clientModel)).willAnswer { roles.stream() }

            val actualToken = transformDockerResponseToken()
            assertEquals(1, actualToken.accessItems.size)

            val expectedActions = setOf(ACTION_PULL)
            TestUtils.assertSameContent(expectedActions, actualToken.accessItems.first().actions)
        }

        @Test
        internal fun user_with_other_namespace_group_and_with_admin_role_on_repository_plugin_scope_push_with_namespace() {

            logCurrentTestMethodName()

            val expectedScope = SCOPE_REPO_PLUGIN_NAMESPACE_PUSH
            given(clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM)).willReturn(expectedScope)
            assertEquals(expectedScope, clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM))

            val groups = TestUtils.createGroupsByNames(GROUP_NAMESPACE_OTHER)
            given(userModel.groupsStream).willAnswer { groups.stream() }
            assertEquals(groups, userModel.groupsStream.toList())

            val roles = TestUtils.createClientRolesByNames(ROLE_ADMIN)
            given(userModel.getClientRoleMappingsStream(clientModel)).willAnswer { roles.stream() }

            val actualToken = transformDockerResponseToken()
            assertEquals(1, actualToken.accessItems.size)

            val expectedActions = setOf(ACTION_PUSH)
            TestUtils.assertSameContent(expectedActions, actualToken.accessItems.first().actions)
        }

        @Test
        internal fun user_with_other_namespace_group_and_with_admin_role_on_repository_plugin_scope_push_without_namespace() {

            logCurrentTestMethodName()

            val expectedScope = SCOPE_REPO_PLUGIN_PUSH
            given(clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM)).willReturn(expectedScope)
            assertEquals(expectedScope, clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM))

            val groups = TestUtils.createGroupsByNames(GROUP_NAMESPACE_OTHER)
            given(userModel.groupsStream).willAnswer { groups.stream() }
            assertEquals(groups, userModel.groupsStream.toList())

            val roles = TestUtils.createClientRolesByNames(ROLE_ADMIN)
            given(userModel.getClientRoleMappingsStream(clientModel)).willAnswer { roles.stream() }

            val actualToken = transformDockerResponseToken()
            assertEquals(1, actualToken.accessItems.size)

            val expectedActions = setOf(ACTION_PUSH)
            TestUtils.assertSameContent(expectedActions, actualToken.accessItems.first().actions)
        }

        @Test
        internal fun user_with_other_namespace_group_and_with_admin_role_on_repository_plugin_scope_pull_and_push_with_namespace() {

            logCurrentTestMethodName()

            val expectedScope = SCOPE_REPO_PLUGIN_NAMESPACE_PULL_PUSH
            given(clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM)).willReturn(expectedScope)
            assertEquals(expectedScope, clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM))

            val groups = TestUtils.createGroupsByNames(GROUP_NAMESPACE_OTHER)
            given(userModel.groupsStream).willAnswer { groups.stream() }
            assertEquals(groups, userModel.groupsStream.toList())

            val roles = TestUtils.createClientRolesByNames(ROLE_ADMIN)
            given(userModel.getClientRoleMappingsStream(clientModel)).willAnswer { roles.stream() }

            val actualToken = transformDockerResponseToken()
            assertEquals(1, actualToken.accessItems.size)

            val expectedActions = setOf(ACTION_PUSH, ACTION_PULL)
            TestUtils.assertSameContent(expectedActions, actualToken.accessItems.first().actions)
        }

        @Test
        internal fun user_with_other_namespace_group_and_with_admin_role_on_repository_plugin_scope_pull_and_push_without_namespace() {

            logCurrentTestMethodName()

            val expectedScope = SCOPE_REPO_PLUGIN_PULL_PUSH
            given(clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM)).willReturn(expectedScope)
            assertEquals(expectedScope, clientSession.getNote(DockerAuthV2Protocol.SCOPE_PARAM))

            val groups = TestUtils.createGroupsByNames(GROUP_NAMESPACE_OTHER)
            given(userModel.groupsStream).willAnswer { groups.stream() }
            assertEquals(groups, userModel.groupsStream.toList())

            val roles = TestUtils.createClientRolesByNames(ROLE_ADMIN)
            given(userModel.getClientRoleMappingsStream(clientModel)).willAnswer { roles.stream() }

            val actualToken = transformDockerResponseToken()
            assertEquals(1, actualToken.accessItems.size)

            val expectedActions = setOf(ACTION_PUSH, ACTION_PULL)
            TestUtils.assertSameContent(expectedActions, actualToken.accessItems.first().actions)
        }
    }

}