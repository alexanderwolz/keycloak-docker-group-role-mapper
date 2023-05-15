package de.alexanderwolz.keycloak.docker.mapping

import de.alexanderwolz.keycloak.docker.mapping.test.utils.TestUtils
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.keycloak.representations.docker.DockerAccess
import kotlin.test.assertContentEquals
import kotlin.test.assertSame

internal class KeycloakGroupsAndRolesToDockerScopeMapperTest {

    private val mapper = KeycloakGroupsAndRolesToDockerScopeMapper()

    @Test
    internal fun substitute_actions_with_scope_all() {
        val accessItem = DockerAccess().also {
            it.actions = listOf("*")
        }
        val expectedActions = setOf("push", "pull")
        val actions = mapper.substituteActions(accessItem)
        assertEquals(expectedActions, actions)
    }

    @Test
    internal fun substitute_actions_with_scope_all_and_pull() {
        val accessItem = DockerAccess().also {
            it.actions = listOf("*", "pull")
        }
        val expectedActions = setOf("push", "pull")
        val actions = mapper.substituteActions(accessItem)
        assertEquals(expectedActions, actions)
    }

    @Test
    internal fun calculate_actions_with_scope_all_and_push_roles() {
        val accessItem = DockerAccess().also {
            it.actions = listOf("*")
        }
        val clientRoleNames = listOf("push")
        val expectedActions = setOf("push", "pull")
        val allowedActions = mapper.calculateAllowedActions(accessItem, clientRoleNames)
        TestUtils.assertSameContent(expectedActions, allowedActions)
    }

    @Test
    internal fun calculate_actions_with_scope_push_and_pull_and_no_roles() {
        val accessItem = DockerAccess().also {
            it.actions = listOf("push", "pull")
        }
        val clientRoleNames = listOf("push")
        val expectedActions = setOf("push", "pull")
        val allowedActions = mapper.calculateAllowedActions(accessItem, clientRoleNames)
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