package de.alexanderwolz.keycloak.docker.utils

import de.alexanderwolz.keycloak.docker.mapping.KeycloakGroupsAndRolesToDockerScopeMapper.Companion.ACTION_ALL
import de.alexanderwolz.keycloak.docker.mapping.KeycloakGroupsAndRolesToDockerScopeMapper.Companion.ACTION_ALL_SUBSTITUTE
import de.alexanderwolz.keycloak.docker.mapping.KeycloakGroupsAndRolesToDockerScopeMapper.Companion.ACTION_DELETE
import de.alexanderwolz.keycloak.docker.mapping.KeycloakGroupsAndRolesToDockerScopeMapper.Companion.ACTION_PULL
import de.alexanderwolz.keycloak.docker.mapping.KeycloakGroupsAndRolesToDockerScopeMapper.Companion.ACTION_PUSH
import de.alexanderwolz.keycloak.docker.mapping.KeycloakGroupsAndRolesToDockerScopeMapper.Companion.GROUP_PREFIX
import de.alexanderwolz.keycloak.docker.mapping.KeycloakGroupsAndRolesToDockerScopeMapper.Companion.ROLE_EDITOR
import org.keycloak.models.ClientModel
import org.keycloak.models.UserModel

class MapperUtils {

    companion object {

        fun getClientRoleNames(user: UserModel, client: ClientModel): Collection<String> {
            return user.getClientRoleMappingsStream(client).map { it.name }.toList()
        }

        fun getUserNamespacesFromGroups(user: UserModel): Collection<String> {
            return user.groupsStream.filter { it.name.startsWith(GROUP_PREFIX) }
                .map { it.name.lowercase().replace(GROUP_PREFIX, "") }.toList()
        }

        fun hasAllPrivileges(actions: Collection<String>, requestedActions: Collection<String>): Boolean {
            return isSubstituteWithAll(actions, requestedActions) || actions.containsAll(requestedActions)
        }

        private fun isSubstituteWithAll(
            actions: Collection<String>, requestedActions: Collection<String>
        ): Boolean {
            return requestedActions.size == 1 && requestedActions.first() == ACTION_ALL && actions.containsAll(
                ACTION_ALL_SUBSTITUTE
            )
        }

        fun getNamespaceFromRepositoryName(repositoryName: String): String? {
            val parts = repositoryName.split("/")
            if (parts.size == 2) {
                return parts[0].lowercase()
            }
            return null
        }

        fun getDomainFromEmail(email: String): String? {
            val parts = email.split("@")
            if (parts.size == 2) {
                return parts[1].lowercase()
            }
            return null //no valid domain
        }

        fun getSecondLevelDomainFromEmail(email: String): String? {
            val domain = getDomainFromEmail(email) ?: return null
            val parts = domain.split(".")
            if (parts.size > 1) {
                return parts[parts.size - 2]
            }
            return null
        }

        // replaces '*' by pull, push and delete
        fun substituteRequestedActions(requestedActions: Collection<String>): List<String> {
            return HashSet(requestedActions).also { actions ->
                if (actions.contains(ACTION_ALL)) {
                    actions.remove(ACTION_ALL)
                    actions.addAll(ACTION_ALL_SUBSTITUTE)
                }
            }.toList()
        }

        fun filterAllowedActions(
            requestedActions: Collection<String>,
            clientRoleNames: Collection<String>,
        ): List<String> {
            val allowedActions = ArrayList<String>()
            val shallAddPrivilegedActions = clientRoleNames.contains(ROLE_EDITOR)
            substituteRequestedActions(requestedActions).forEach { action ->
                if (ACTION_PUSH == action && shallAddPrivilegedActions) {
                    allowedActions.add(action)
                }
                if (ACTION_DELETE == action && shallAddPrivilegedActions) {
                    allowedActions.add(action)
                }
                if (ACTION_PULL == action) {
                    //all users in namespace group can pull images (read only by default)
                    allowedActions.add(action)
                }
            }
            return allowedActions
        }

    }
}