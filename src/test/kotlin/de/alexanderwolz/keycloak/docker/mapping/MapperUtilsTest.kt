package de.alexanderwolz.keycloak.docker.mapping

import de.alexanderwolz.keycloak.docker.mapping.KeycloakGroupsAndRolesToDockerScopeMapper.Companion.ACTION_ALL
import de.alexanderwolz.keycloak.docker.mapping.KeycloakGroupsAndRolesToDockerScopeMapper.Companion.ACTION_ALL_SUBSTITUTE
import de.alexanderwolz.keycloak.docker.mapping.KeycloakGroupsAndRolesToDockerScopeMapper.Companion.ACTION_DELETE
import de.alexanderwolz.keycloak.docker.mapping.KeycloakGroupsAndRolesToDockerScopeMapper.Companion.ACTION_PULL
import de.alexanderwolz.keycloak.docker.mapping.KeycloakGroupsAndRolesToDockerScopeMapper.Companion.ACTION_PUSH
import de.alexanderwolz.keycloak.docker.mapping.KeycloakGroupsAndRolesToDockerScopeMapper.Companion.GROUP_PREFIX
import de.alexanderwolz.keycloak.docker.mapping.KeycloakGroupsAndRolesToDockerScopeMapper.Companion.ROLE_EDITOR
import de.alexanderwolz.keycloak.docker.utils.MapperUtils
import org.junit.jupiter.api.Test
import org.keycloak.models.ClientModel
import org.keycloak.models.GroupModel
import org.keycloak.models.RoleModel
import org.keycloak.models.UserModel
import org.mockito.Mockito
import org.mockito.kotlin.given
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

class MapperUtilsTest {

    @Test
    internal fun test_get_client_role_names() {
        val client = Mockito.mock(ClientModel::class.java)
        given(client.clientId).willReturn("client")
        val user = Mockito.mock(UserModel::class.java)

        val expectedRoleNames = setOf(ROLE_EDITOR, "otherRoleWithCamelCase")
        given(user.getClientRoleMappingsStream(client)).willAnswer {
            expectedRoleNames.map { roleName ->
                Mockito.mock(RoleModel::class.java).also {
                    given(it.name).willReturn(roleName)
                }
            }.stream()
        }
        val roleNames = MapperUtils.getClientRoleNames(user, client)
        assertEquals(expectedRoleNames.sorted(), roleNames.sorted())
    }

    @Test
    internal fun test_get_user_namespaces_from_groups() {
        val user = Mockito.mock(UserModel::class.java)

        val groupNames = setOf("${GROUP_PREFIX}company", "otherGroup")
        given(user.groupsStream).willAnswer {
            groupNames.map { groupName ->
                Mockito.mock(GroupModel::class.java).also {
                    given(it.name).willReturn(groupName)
                }
            }.stream()
        }

        val expectedGroupNames = setOf("company")
        val actualGroupNames = MapperUtils.getUserNamespacesFromGroups(user)
        assertEquals(expectedGroupNames.sorted(), actualGroupNames.sorted())
    }

    @Test
    internal fun test_has_all_privileges_with_substitute() {
        val requestedActions = setOf(ACTION_ALL)
        val actions = ACTION_ALL_SUBSTITUTE
        val hasAllPrivileges = MapperUtils.hasAllPrivileges(actions, requestedActions)
        assertTrue(hasAllPrivileges)
    }

    @Test
    internal fun test_has_all_privileges() {
        val requestedActions = setOf(ACTION_PULL, ACTION_DELETE)
        val actions = setOf(ACTION_DELETE, ACTION_PULL)
        val hasAllPrivileges = MapperUtils.hasAllPrivileges(actions, requestedActions)
        assertTrue(hasAllPrivileges)
    }

    @Test
    internal fun test_has_not_all_privileges() {
        val requestedActions = setOf(ACTION_PUSH)
        val actions = setOf(ACTION_PULL)
        val hasAllPrivileges = MapperUtils.hasAllPrivileges(actions, requestedActions)
        assertFalse(hasAllPrivileges)
    }

    @Test
    internal fun test_get_namespace_from_repository_name_returns_namespace() {
        val namespace = MapperUtils.getNamespaceFromRepositoryName("company/image")
        assertEquals("company", namespace)
    }

    @Test
    internal fun test_get_namespace_from_repository_name_returns_null() {
        val namespace = MapperUtils.getNamespaceFromRepositoryName("image")
        assertNull(namespace)
    }

    @Test
    internal fun test_get_namespace_from_repository_name_returns_null_on_wrong_syntax() {
        val namespace = MapperUtils.getNamespaceFromRepositoryName("some/other/string")
        assertNull(namespace)
    }

    @Test
    internal fun test_is_email() {
        val domain = MapperUtils.getDomainFromEmail("john.doe@company.com")
        assertEquals("company.com", domain)
    }

    @Test
    internal fun test_is_not_email() {
        val domain = MapperUtils.getDomainFromEmail("john.doe")
        assertNull(domain)
    }

    @Test
    internal fun test_second_level_domain() {
        val sld = MapperUtils.getSecondLevelDomainFromEmail("john.doe@company.com")
        assertEquals("company", sld)
    }

    @Test
    internal fun test_second_level_domain_with_subdomain() {
        val sld = MapperUtils.getSecondLevelDomainFromEmail("john.doe@mail.company.com")
        assertEquals("company", sld)
    }

    @Test
    internal fun test_second_level_domain_with_invalid_email() {
        val sld = MapperUtils.getSecondLevelDomainFromEmail("john.doe")
        assertNull(sld)
    }

    @Test
    internal fun substitute_actions_with_scope_all() {
        val requestedActions = listOf(ACTION_ALL)
        val expectedActions = setOf("pull", "push", "delete")
        val actions = MapperUtils.substituteRequestedActions(requestedActions)
        assertEquals(expectedActions.sorted(), actions.sorted())
    }

    @Test
    internal fun substitute_actions_with_scope_all_and_pull() {
        val requestedActions = listOf(ACTION_ALL, ACTION_PULL)
        val expectedActions = setOf("pull", "push", "delete")
        val actions = MapperUtils.substituteRequestedActions(requestedActions)
        assertEquals(expectedActions.sorted(), actions.sorted())
    }

    @Test
    internal fun test_filter_allowed_actions_with_action_all_for_user() {
        val requestedActions = setOf(ACTION_ALL)
        val clientRoleNames = emptySet<String>()
        val allowedActions = MapperUtils.filterAllowedActions(requestedActions, clientRoleNames)
        val expectedActions = setOf(ACTION_PULL)
        assertEquals(expectedActions.sorted(), allowedActions.sorted())
    }

    @Test
    internal fun test_filter_allowed_actions_with_action_pull_for_user() {
        val requestedActions = setOf(ACTION_PULL)
        val clientRoleNames = emptySet<String>()
        val allowedActions = MapperUtils.filterAllowedActions(requestedActions, clientRoleNames)
        val expectedActions = setOf(ACTION_PULL)
        assertEquals(expectedActions.sorted(), allowedActions.sorted())
    }

    @Test
    internal fun test_filter_allowed_actions_with_action_push_for_user() {
        val requestedActions = setOf(ACTION_PUSH)
        val clientRoleNames = emptySet<String>()
        val allowedActions = MapperUtils.filterAllowedActions(requestedActions, clientRoleNames)
        val expectedActions = emptySet<String>()
        assertEquals(expectedActions.sorted(), allowedActions.sorted())
    }

    @Test
    internal fun test_filter_allowed_actions_with_action_delete_for_user() {
        val requestedActions = setOf(ACTION_DELETE)
        val clientRoleNames = emptySet<String>()
        val allowedActions = MapperUtils.filterAllowedActions(requestedActions, clientRoleNames)
        val expectedActions = emptySet<String>()
        assertEquals(expectedActions.sorted(), allowedActions.sorted())
    }

    @Test
    internal fun test_filter_allowed_actions_with_action_pull_push_for_user() {
        val requestedActions = setOf(ACTION_PULL, ACTION_PUSH)
        val clientRoleNames = emptySet<String>()
        val allowedActions = MapperUtils.filterAllowedActions(requestedActions, clientRoleNames)
        val expectedActions = setOf(ACTION_PULL)
        assertEquals(expectedActions.sorted(), allowedActions.sorted())
    }

    @Test
    internal fun test_filter_allowed_actions_with_action_all_for_editor() {
        val requestedActions = setOf(ACTION_ALL)
        val clientRoleNames = setOf(ROLE_EDITOR)
        val allowedActions = MapperUtils.filterAllowedActions(requestedActions, clientRoleNames)
        val expectedActions = ACTION_ALL_SUBSTITUTE
        assertEquals(expectedActions.sorted(), allowedActions.sorted())
    }

    @Test
    internal fun test_filter_allowed_actions_with_action_pull_for_editor() {
        val requestedActions = setOf(ACTION_PULL)
        val clientRoleNames = setOf(ROLE_EDITOR)
        val allowedActions = MapperUtils.filterAllowedActions(requestedActions, clientRoleNames)
        val expectedActions = setOf(ACTION_PULL)
        assertEquals(expectedActions.sorted(), allowedActions.sorted())
    }

    @Test
    internal fun test_filter_allowed_actions_with_action_push_for_editor() {
        val requestedActions = setOf(ACTION_PUSH)
        val clientRoleNames = setOf(ROLE_EDITOR)
        val allowedActions = MapperUtils.filterAllowedActions(requestedActions, clientRoleNames)
        val expectedActions = setOf(ACTION_PUSH)
        assertEquals(expectedActions.sorted(), allowedActions.sorted())
    }

    @Test
    internal fun test_filter_allowed_actions_with_action_delete_for_editor() {
        val requestedActions = setOf(ACTION_DELETE)
        val clientRoleNames = setOf(ROLE_EDITOR)
        val allowedActions = MapperUtils.filterAllowedActions(requestedActions, clientRoleNames)
        val expectedActions = setOf(ACTION_DELETE)
        assertEquals(expectedActions.sorted(), allowedActions.sorted())
    }

    @Test
    internal fun test_filter_allowed_actions_with_action_pull_push_for_editor() {
        val requestedActions = setOf(ACTION_PULL, ACTION_PUSH)
        val clientRoleNames = setOf(ROLE_EDITOR)
        val allowedActions = MapperUtils.filterAllowedActions(requestedActions, clientRoleNames)
        val expectedActions = setOf(ACTION_PULL, ACTION_PUSH)
        assertEquals(expectedActions.sorted(), allowedActions.sorted())
    }

}