package de.alexanderwolz.keycloak.docker.mapping

import de.alexanderwolz.keycloak.docker.mapping.AbstractDockerScopeMapper.Companion.ACTION_ALL
import de.alexanderwolz.keycloak.docker.mapping.AbstractDockerScopeMapper.Companion.ACTION_DELETE
import de.alexanderwolz.keycloak.docker.mapping.AbstractDockerScopeMapper.Companion.ACTION_PULL
import de.alexanderwolz.keycloak.docker.mapping.AbstractDockerScopeMapper.Companion.ACTION_PUSH
import org.junit.jupiter.api.Test
import org.keycloak.models.GroupModel
import org.keycloak.models.UserModel
import org.mockito.Mockito
import org.mockito.kotlin.given
import kotlin.test.assertEquals

internal class KeycloakGroupsAndRolesToDockerScopeMapperTest {

    private val mapper = KeycloakGroupsAndRolesToDockerScopeMapper()

    @Test
    fun testGetUserNamespacesFromGroups() {
        val user = Mockito.mock(UserModel::class.java)
        val groupNames = setOf("${KeycloakGroupsAndRolesToDockerScopeMapper.GROUP_PREFIX}company", "otherGroup")
        given(user.groupsStream).willAnswer {
            groupNames.map { groupName ->
                Mockito.mock(GroupModel::class.java).also {
                    given(it.name).willReturn(groupName)
                }
            }.stream()
        }
        val expectedGroupNames = setOf("company")
        val actualGroupNames = mapper.getUserNamespacesFromGroups(user)
        assertEquals(expectedGroupNames.sorted(), actualGroupNames.sorted())
    }

    @Test
    fun testFilterAllowedActionsAllForUser() {
        val requestedActions = setOf(ACTION_ALL)
        val clientRoleNames = emptySet<String>()
        val allowedActions = mapper.filterAllowedActions(requestedActions, clientRoleNames)
        val expectedActions = setOf(ACTION_PULL)
        assertEquals(expectedActions.sorted(), allowedActions.sorted())
    }

    @Test
    fun testFilterAllowedActionsPullForUser() {
        val requestedActions = setOf(ACTION_PULL)
        val clientRoleNames = emptySet<String>()
        val allowedActions = mapper.filterAllowedActions(requestedActions, clientRoleNames)
        val expectedActions = setOf(ACTION_PULL)
        assertEquals(expectedActions.sorted(), allowedActions.sorted())
    }

    @Test
    fun testFilterAllowedActionsPushForUser() {
        val requestedActions = setOf(ACTION_PUSH)
        val clientRoleNames = emptySet<String>()
        val allowedActions = mapper.filterAllowedActions(requestedActions, clientRoleNames)
        val expectedActions = emptySet<String>()
        assertEquals(expectedActions.sorted(), allowedActions.sorted())
    }

    @Test
    fun testFilterAllowedActionsDeleteForUser() {
        val requestedActions = setOf(ACTION_DELETE)
        val clientRoleNames = emptySet<String>()
        val allowedActions = mapper.filterAllowedActions(requestedActions, clientRoleNames)
        val expectedActions = emptySet<String>()
        assertEquals(expectedActions.sorted(), allowedActions.sorted())
    }

    @Test
    fun testFilterAllowedActionsPullPushForUser() {
        val requestedActions = setOf(ACTION_PULL, ACTION_PUSH)
        val clientRoleNames = emptySet<String>()
        val allowedActions = mapper.filterAllowedActions(requestedActions, clientRoleNames)
        val expectedActions = setOf(ACTION_PULL)
        assertEquals(expectedActions.sorted(), allowedActions.sorted())
    }

    @Test
    fun testFilterAllowedActionsPullPushDeleteForUser() {
        val requestedActions = setOf(ACTION_PULL, ACTION_PUSH, ACTION_DELETE)
        val clientRoleNames = emptySet<String>()
        val allowedActions = mapper.filterAllowedActions(requestedActions, clientRoleNames)
        val expectedActions = setOf(ACTION_PULL)
        assertEquals(expectedActions.sorted(), allowedActions.sorted())
    }

    @Test
    fun testFilterAllowedActionsAllForEditor() {
        val requestedActions = setOf(ACTION_ALL)
        val clientRoleNames = setOf(KeycloakGroupsAndRolesToDockerScopeMapper.ROLE_EDITOR)
        val allowedActions = mapper.filterAllowedActions(requestedActions, clientRoleNames)
        val expectedActions = setOf(ACTION_ALL)
        assertEquals(expectedActions.sorted(), allowedActions.sorted())
    }

    @Test
    fun testFilterAllowedActionsPullForEditor() {
        val requestedActions = setOf(ACTION_PULL)
        val clientRoleNames = setOf(KeycloakGroupsAndRolesToDockerScopeMapper.ROLE_EDITOR)
        val allowedActions = mapper.filterAllowedActions(requestedActions, clientRoleNames)
        val expectedActions = setOf(ACTION_PULL)
        assertEquals(expectedActions.sorted(), allowedActions.sorted())
    }

    @Test
    fun testFilterAllowedActionsPushForEditor() {
        val requestedActions = setOf(ACTION_PUSH)
        val clientRoleNames = setOf(KeycloakGroupsAndRolesToDockerScopeMapper.ROLE_EDITOR)
        val allowedActions = mapper.filterAllowedActions(requestedActions, clientRoleNames)
        val expectedActions = setOf(ACTION_PUSH)
        assertEquals(expectedActions.sorted(), allowedActions.sorted())
    }

    @Test
    fun testFilterAllowedActionsDeleteForEditor() {
        val requestedActions = setOf(ACTION_DELETE)
        val clientRoleNames = setOf(KeycloakGroupsAndRolesToDockerScopeMapper.ROLE_EDITOR)
        val allowedActions = mapper.filterAllowedActions(requestedActions, clientRoleNames)
        val expectedActions = setOf(ACTION_DELETE)
        assertEquals(expectedActions.sorted(), allowedActions.sorted())
    }

    @Test
    fun testFilterAllowedActionsPullPushForEditor() {
        val requestedActions = setOf(ACTION_PULL, ACTION_PUSH)
        val clientRoleNames = setOf(KeycloakGroupsAndRolesToDockerScopeMapper.ROLE_EDITOR)
        val allowedActions = mapper.filterAllowedActions(requestedActions, clientRoleNames)
        val expectedActions = setOf(ACTION_PULL, ACTION_PUSH)
        assertEquals(expectedActions.sorted(), allowedActions.sorted())
    }

    @Test
    fun testFilterAllowedActionsPullPushDeleteForEditor() {
        val requestedActions = setOf(ACTION_PULL, ACTION_PUSH, ACTION_DELETE)
        val clientRoleNames = setOf(KeycloakGroupsAndRolesToDockerScopeMapper.ROLE_EDITOR)
        val allowedActions = mapper.filterAllowedActions(requestedActions, clientRoleNames)
        val expectedActions = setOf(ACTION_PULL, ACTION_PUSH, ACTION_DELETE)
        assertEquals(expectedActions.sorted(), allowedActions.sorted())
    }

}