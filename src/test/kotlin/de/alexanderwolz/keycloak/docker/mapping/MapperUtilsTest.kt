package de.alexanderwolz.keycloak.docker.mapping

import de.alexanderwolz.keycloak.docker.mapping.KeycloakGroupsAndRolesToDockerScopeMapper.Companion.ACTION_ALL
import de.alexanderwolz.keycloak.docker.mapping.KeycloakGroupsAndRolesToDockerScopeMapper.Companion.ACTION_PULL
import de.alexanderwolz.keycloak.docker.utils.MapperUtils
import org.junit.jupiter.api.Test
import kotlin.test.assertEquals

class MapperUtilsTest {

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
    internal fun test_is_email(){
        val domain = MapperUtils.getDomainFromEmail("john.doe@company.com")
        assertEquals("company.com",domain)
    }


//    @Test
//    internal fun calculate_actions_with_scope_all_and_editor_roles() {
//        val accessItem = DockerAccess().also {
//            it.name = "johnny/image"
//            it.actions = listOf("*")
//        }
//        val clientRoleNames = listOf(KeycloakGroupsAndRolesToDockerScopeMapper.ROLE_EDITOR)
//        val expectedActions = setOf("pull", "push", "delete")
//        val allowedActions = MapperUtils.calculateAllowedActions(accessItem, clientRoleNames, "Johnny")
//        Assertions.assertEquals(expectedActions.sorted(), allowedActions.sorted())
//    }
//
//    @Test
//    internal fun calculate_actions_with_scope_push_and_pull_and_no_roles() {
//        val accessItem = DockerAccess().also {
//            it.name = "johnny/image"
//            it.actions = listOf("push", "pull")
//        }
//        val expectedActions = setOf("pull")
//        val allowedActions = MapperUtils.calculateAllowedActions(accessItem, emptySet(), "Johnny")
//        Assertions.assertEquals(expectedActions.sorted(), allowedActions.sorted())
//    }
//
//    @Test
//    internal fun calculate_actions_with_scope_all_and_no_roles() {
//        val accessItem = DockerAccess().also {
//            it.name = "johnny/image"
//            it.actions = listOf("*")
//        }
//        val expectedActions = setOf("pull")
//        val allowedActions = MapperUtils.calculateAllowedActions(accessItem, emptySet(), "Johnny")
//        Assertions.assertEquals(expectedActions.sorted(), allowedActions.sorted())
//    }

}