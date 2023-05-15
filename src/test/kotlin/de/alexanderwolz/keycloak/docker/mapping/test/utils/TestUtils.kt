package de.alexanderwolz.keycloak.docker.mapping.test.utils

import org.junit.jupiter.api.Assertions
import org.keycloak.models.GroupModel
import org.keycloak.models.RoleModel
import org.mockito.BDDMockito
import org.mockito.Mockito

class TestUtils {

    companion object {

        fun createGroupsByNames(vararg names: String): Collection<GroupModel> {
            val groups = ArrayList<GroupModel>()
            names.forEach {
                val group = Mockito.mock(GroupModel::class.java)
                BDDMockito.given(group.name).willReturn(it)
                groups.add(group)
            }
            return groups
        }

        fun createClientRolesByNames(vararg names: String): Collection<RoleModel> {
            val roles = ArrayList<RoleModel>()
            names.forEach {
                val role = Mockito.mock(RoleModel::class.java)
                BDDMockito.given(role.name).willReturn(it)
                roles.add(role)
            }
            return roles
        }

        fun <T> assertSameContent(expected: Collection<T>, actual: Collection<T>) {
            Assertions.assertEquals(expected.size, actual.size)
            Assertions.assertTrue(expected.containsAll(actual))
            Assertions.assertTrue(actual.containsAll(expected))
        }

    }
}