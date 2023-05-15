package de.alexanderwolz.keycloak.docker.mapping

import de.alexanderwolz.keycloak.docker.mapping.test.utils.TestUtils
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import org.keycloak.representations.docker.DockerAccess
import de.alexanderwolz.keycloak.docker.mapping.KeycloakGroupsAndRolesToDockerScopeMapper as MapperToTest

internal class KeycloakGroupsAndRolesToDockerScopeMapperTest {

    private val mapper = MapperToTest()

    @Test
    internal fun substitute_actions_with_scope_all() {
        val accessItem = DockerAccess().also {
            it.actions = listOf("*")
        }
        val expectedActions = setOf("pull", "push", "delete")
        val actions = mapper.substituteActions(accessItem)
        assertEquals(expectedActions, actions)
    }

    @Test
    internal fun substitute_actions_with_scope_all_and_pull() {
        val accessItem = DockerAccess().also {
            it.actions = listOf("*", "pull")
        }
        val expectedActions = setOf("pull", "push", "delete")
        val actions = mapper.substituteActions(accessItem)
        assertEquals(expectedActions, actions)
    }

    @Test
    internal fun calculate_actions_with_scope_all_and_editor_roles() {
        val accessItem = DockerAccess().also {
            it.actions = listOf("*")
        }
        val clientRoleNames = listOf(MapperToTest.ROLE_EDITOR)
        val expectedActions = setOf("pull", "push", "delete")
        val allowedActions = mapper.calculateAllowedActions(accessItem, clientRoleNames)
        TestUtils.assertSameContent(expectedActions, allowedActions)
    }

    @Test
    internal fun calculate_actions_with_scope_push_and_pull_and_no_roles() {
        val accessItem = DockerAccess().also {
            it.actions = listOf("push", "pull")
        }
        val expectedActions = setOf("pull")
        val allowedActions = mapper.calculateAllowedActions(accessItem, emptySet())
        TestUtils.assertSameContent(expectedActions, allowedActions)
    }

    @Test
    internal fun calculate_actions_with_scope_all_and_no_roles() {
        val accessItem = DockerAccess().also {
            it.actions = listOf("*")
        }
        val expectedActions = setOf("pull")
        val allowedActions = mapper.calculateAllowedActions(accessItem, emptySet())
        TestUtils.assertSameContent(expectedActions, allowedActions)
    }

}