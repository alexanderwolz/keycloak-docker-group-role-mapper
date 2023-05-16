package de.alexanderwolz.keycloak.docker.mapping.testsuite

import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test

class AdminTestSuite : AbstractScopeMapperTestSuite() {

    // Definition editor:  a person with role 'editor' but not 'admin'
    // Editors can pull, push and delete on repositories in their namespace

    override fun setRoles(vararg roleNames: String) {
        super.setRoles(ROLE_ADMIN, *roleNames)
    }

    @Test
    internal fun admin_no_groups_on_empty_scope() {
        assertEmptyAccessItems()
    }

    @Nested
    inner class RegistryTests {

        @Test
        internal fun admin_no_groups_on_registry_other_scope_all() {
            setScope(SCOPE_REGISTRY_OTHER_ALL)
            assertContainsOneAccessItemWithActions(ACTION_ALL)
        }

        @Test
        internal fun admin_other_groups_on_registry_other_scope_all() {
            setGroups(GROUP_NAMESPACE_OTHER)
            setScope(SCOPE_REGISTRY_OTHER_ALL)
            assertContainsOneAccessItemWithActions(ACTION_ALL)
        }

        @Test
        internal fun admin_namespace_groups_on_registry_other_scope_all() {
            setGroups(GROUP_NAMESPACE)
            setScope(SCOPE_REGISTRY_OTHER_ALL)
            assertContainsOneAccessItemWithActions(ACTION_ALL)
        }
    }

    @Nested
    inner class RegistryCatalogTests {

        @Test
        internal fun admin_no_groups_on_registry_catalog_scope_all() {
            setScope(SCOPE_REGISTRY_CATALOG_ALL)
            assertContainsOneAccessItemWithActions(ACTION_ALL)
        }

        @Test
        internal fun admin_other_groups_on_registry_catalog_scope_all() {
            setGroups(GROUP_NAMESPACE_OTHER)
            setScope(SCOPE_REGISTRY_CATALOG_ALL)
            assertContainsOneAccessItemWithActions(ACTION_ALL)
        }

        @Test
        internal fun admin_namespace_groups_on_registry_catalog_scope_all() {
            setGroups(GROUP_NAMESPACE)
            setScope(SCOPE_REGISTRY_CATALOG_ALL)
            assertContainsOneAccessItemWithActions(ACTION_ALL)
        }
    }

    @Nested
    inner class RegistryCatalogScopeForAudienceUserTests {

        @Test
        internal fun admin_no_groups_on_registry_catalog_scope_all_audience_user() {
            setScope(SCOPE_REGISTRY_CATALOG_ALL)
            setAudience(AUDIENCE_USER)
            assertContainsOneAccessItemWithActions(ACTION_ALL)
        }

        @Test
        internal fun admin_other_groups_on_registry_catalog_scope_all_audience_user() {
            setGroups(GROUP_NAMESPACE_OTHER)
            setScope(SCOPE_REGISTRY_CATALOG_ALL)
            setAudience(AUDIENCE_USER)
            assertContainsOneAccessItemWithActions(ACTION_ALL)
        }

        @Test
        internal fun admin_namespace_groups_on_registry_catalog_scope_all_audience_user() {
            setGroups(GROUP_NAMESPACE)
            setScope(SCOPE_REGISTRY_CATALOG_ALL)
            setAudience(AUDIENCE_USER)
            assertContainsOneAccessItemWithActions(ACTION_ALL)
        }
    }

    @Nested
    inner class RegistryCatalogScopeForAudienceEditorTests {

        @Test
        internal fun admin_no_groups_on_registry_catalog_scope_all_audience_editor() {
            setScope(SCOPE_REGISTRY_CATALOG_ALL)
            setAudience(AUDIENCE_EDITOR)
            assertContainsOneAccessItemWithActions(ACTION_ALL)
        }

        @Test
        internal fun admin_other_groups_on_registry_catalog_scope_all_audience_editor() {
            setGroups(GROUP_NAMESPACE_OTHER)
            setScope(SCOPE_REGISTRY_CATALOG_ALL)
            setAudience(AUDIENCE_EDITOR)
            assertContainsOneAccessItemWithActions(ACTION_ALL)
        }

        @Test
        internal fun admin_namespace_groups_on_registry_catalog_scope_all_audience_editor() {
            setGroups(GROUP_NAMESPACE)
            setScope(SCOPE_REGISTRY_CATALOG_ALL)
            setAudience(AUDIENCE_EDITOR)
            assertContainsOneAccessItemWithActions(ACTION_ALL)
        }
    }

    @Nested
    inner class RegistryCatalogScopeForAudienceUserAndEditorTests {

        @Test
        internal fun admin_no_groups_on_registry_catalog_scope_all_audience_user_and_editor() {
            setScope(SCOPE_REGISTRY_CATALOG_ALL)
            setAudience(AUDIENCE_USER, AUDIENCE_EDITOR)
            assertContainsOneAccessItemWithActions(ACTION_ALL)
        }

        @Test
        internal fun admin_other_groups_on_registry_catalog_scope_all_audience_user_and_editor() {
            setGroups(GROUP_NAMESPACE_OTHER)
            setScope(SCOPE_REGISTRY_CATALOG_ALL)
            setAudience(AUDIENCE_USER, AUDIENCE_EDITOR)
            assertContainsOneAccessItemWithActions(ACTION_ALL)
        }

        @Test
        internal fun admin_namespace_groups_on_registry_catalog_scope_all_audience_editor() {
            setGroups(GROUP_NAMESPACE)
            setScope(SCOPE_REGISTRY_CATALOG_ALL)
            setAudience(AUDIENCE_USER, AUDIENCE_EDITOR)
            assertContainsOneAccessItemWithActions(ACTION_ALL)
        }
    }

    @Nested
    inner class DefaultRepositoryNoGroupsTests {

        @Test
        internal fun admin_no_groups_on_repository_scope_all_default() {
            setScope(SCOPE_REPO_DEFAULT_ALL)
            assertContainsOneAccessItemWithActions(ACTION_ALL)
        }

        @Test
        internal fun admin_no_groups_on_repository_scope_pull_default() {
            setScope(SCOPE_REPO_DEFAULT_PULL)
            assertContainsOneAccessItemWithActions(ACTION_PULL)
        }

        @Test
        internal fun admin_no_groups_on_repository_scope_push_default() {
            setScope(SCOPE_REPO_DEFAULT_PUSH)
            assertContainsOneAccessItemWithActions(ACTION_PUSH)
        }

        @Test
        internal fun admin_no_groups_on_repository_scope_delete_default() {
            setScope(SCOPE_REPO_DEFAULT_DELETE)
            assertContainsOneAccessItemWithActions(ACTION_DELETE)
        }

        @Test
        internal fun admin_no_groups_on_repository_scope_pull_push_default() {
            setScope(SCOPE_REPO_DEFAULT_PULL_PUSH)
            assertContainsOneAccessItemWithActions(ACTION_PULL, ACTION_PUSH)
        }
    }

    @Nested
    inner class DefaultRepositoryOtherGroupsTests {

        @Test
        internal fun admin_other_groups_on_repository_scope_all_default() {
            setGroups(GROUP_NAMESPACE_OTHER)
            setScope(SCOPE_REPO_DEFAULT_ALL)
            assertContainsOneAccessItemWithActions(ACTION_ALL)
        }

        @Test
        internal fun admin_other_groups_on_repository_scope_pull_default() {
            setGroups(GROUP_NAMESPACE_OTHER)
            setScope(SCOPE_REPO_DEFAULT_PULL)
            assertContainsOneAccessItemWithActions(ACTION_PULL)
        }

        @Test
        internal fun admin_other_groups_on_repository_scope_push_default() {
            setGroups(GROUP_NAMESPACE_OTHER)
            setScope(SCOPE_REPO_DEFAULT_PUSH)
            assertContainsOneAccessItemWithActions(ACTION_PUSH)
        }

        @Test
        internal fun admin_other_groups_on_repository_scope_delete_default() {
            setGroups(GROUP_NAMESPACE_OTHER)
            setScope(SCOPE_REPO_DEFAULT_DELETE)
            assertContainsOneAccessItemWithActions(ACTION_DELETE)
        }

        @Test
        internal fun admin_other_groups_on_repository_scope_pull_push_default() {
            setGroups(GROUP_NAMESPACE_OTHER)
            setScope(SCOPE_REPO_DEFAULT_PULL_PUSH)
            assertContainsOneAccessItemWithActions(ACTION_PULL, ACTION_PUSH)
        }
    }

    @Nested
    inner class DefaultRepositoryNamespaceGroupsTests {

        @Test
        internal fun admin_namespace_groups_on_repository_scope_all_default() {
            setGroups(GROUP_NAMESPACE)
            setScope(SCOPE_REPO_DEFAULT_ALL)
            assertContainsOneAccessItemWithActions(ACTION_ALL)
        }

        @Test
        internal fun admin_namespace_groups_on_repository_scope_pull_default() {
            setGroups(GROUP_NAMESPACE)
            setScope(SCOPE_REPO_DEFAULT_PULL)
            assertContainsOneAccessItemWithActions(ACTION_PULL)
        }

        @Test
        internal fun admin_namespace_groups_on_repository_scope_push_default() {
            setGroups(GROUP_NAMESPACE)
            setScope(SCOPE_REPO_DEFAULT_PUSH)
            assertContainsOneAccessItemWithActions(ACTION_PUSH)
        }

        @Test
        internal fun admin_namespace_groups_on_repository_scope_delete_default() {
            setGroups(GROUP_NAMESPACE)
            setScope(SCOPE_REPO_DEFAULT_DELETE)
            assertContainsOneAccessItemWithActions(ACTION_DELETE)
        }

        @Test
        internal fun admin_namespace_groups_on_repository_scope_pull_push_default() {
            setGroups(GROUP_NAMESPACE)
            setScope(SCOPE_REPO_DEFAULT_PULL_PUSH)
            assertContainsOneAccessItemWithActions(ACTION_PULL, ACTION_PUSH)
        }
    }

    @Nested
    inner class NamespaceRepositoryNoGroupsTests {
        @Test
        internal fun admin_no_groups_on_repository_scope_all_namespace() {
            setScope(SCOPE_REPO_NAMESPACE_ALL)
            assertContainsOneAccessItemWithActions(ACTION_ALL)
        }

        @Test
        internal fun admin_no_groups_on_repository_scope_pull_namespace() {
            setScope(SCOPE_REPO_NAMESPACE_PULL)
            assertContainsOneAccessItemWithActions(ACTION_PULL)
        }

        @Test
        internal fun admin_no_groups_on_repository_scope_push_namespace() {
            setScope(SCOPE_REPO_NAMESPACE_PUSH)
            assertContainsOneAccessItemWithActions(ACTION_PUSH)
        }

        @Test
        internal fun admin_no_groups_on_repository_scope_delete_namespace() {
            setScope(SCOPE_REPO_NAMESPACE_DELETE)
            assertContainsOneAccessItemWithActions(ACTION_DELETE)
        }

        @Test
        internal fun admin_no_groups_on_repository_scope_pull_push_namespace() {
            setScope(SCOPE_REPO_NAMESPACE_PULL_PUSH)
            assertContainsOneAccessItemWithActions(ACTION_PULL, ACTION_PUSH)
        }
    }

    @Nested
    inner class NamespaceRepositoryOtherGroupsTests {
        @Test
        internal fun admin_other_groups_on_repository_scope_all_namespace() {
            setGroups(GROUP_NAMESPACE_OTHER)
            setScope(SCOPE_REPO_NAMESPACE_ALL)
            assertContainsOneAccessItemWithActions(ACTION_ALL)
        }

        @Test
        internal fun admin_other_groups_on_repository_scope_pull_namespace() {
            setGroups(GROUP_NAMESPACE_OTHER)
            setScope(SCOPE_REPO_NAMESPACE_PULL)
            assertContainsOneAccessItemWithActions(ACTION_PULL)
        }

        @Test
        internal fun admin_other_groups_on_repository_scope_push_namespace() {
            setGroups(GROUP_NAMESPACE_OTHER)
            setScope(SCOPE_REPO_NAMESPACE_PUSH)
            assertContainsOneAccessItemWithActions(ACTION_PUSH)
        }

        @Test
        internal fun admin_other_groups_on_repository_scope_delete_namespace() {
            setGroups(GROUP_NAMESPACE_OTHER)
            setScope(SCOPE_REPO_NAMESPACE_DELETE)
            assertContainsOneAccessItemWithActions(ACTION_DELETE)
        }

        @Test
        internal fun admin_other_groups_on_repository_scope_pull_push_namespace() {
            setGroups(GROUP_NAMESPACE_OTHER)
            setScope(SCOPE_REPO_NAMESPACE_PULL_PUSH)
            assertContainsOneAccessItemWithActions(ACTION_PULL, ACTION_PUSH)
        }
    }

    @Nested
    inner class NamespaceRepositoryNamespaceGroupsTests {

        @Test
        internal fun admin_namespace_groups_on_repository_scope_all_namespace() {
            setGroups(GROUP_NAMESPACE)
            setScope(SCOPE_REPO_NAMESPACE_ALL)
            assertContainsOneAccessItemWithActions(ACTION_ALL)
        }

        @Test
        internal fun admin_namespace_groups_on_repository_scope_pull_namespace() {
            setGroups(GROUP_NAMESPACE)
            setScope(SCOPE_REPO_NAMESPACE_PULL)
            assertContainsOneAccessItemWithActions(ACTION_PULL)
        }

        @Test
        internal fun admin_namespace_groups_on_repository_scope_push_namespace() {
            setGroups(GROUP_NAMESPACE)
            setScope(SCOPE_REPO_NAMESPACE_PUSH)
            assertContainsOneAccessItemWithActions(ACTION_PUSH)
        }

        @Test
        internal fun admin_namespace_groups_on_repository_scope_delete_namespace() {
            setGroups(GROUP_NAMESPACE)
            setScope(SCOPE_REPO_NAMESPACE_DELETE)
            assertContainsOneAccessItemWithActions(ACTION_DELETE)
        }

        @Test
        internal fun admin_namespace_groups_on_repository_scope_pull_push_namespace() {
            setGroups(GROUP_NAMESPACE)
            setScope(SCOPE_REPO_NAMESPACE_PULL_PUSH)
            assertContainsOneAccessItemWithActions(ACTION_PULL, ACTION_PUSH)
        }
    }

    @Nested
    inner class NamespaceRepositoryNoGroupsWithUsernameScopeTests {
        @Test
        internal fun admin_no_groups_on_repository_scope_all_namespace_username() {
            setScope(SCOPE_REPO_NAMESPACE_ALL)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME)
            assertContainsOneAccessItemWithActions(ACTION_ALL)
        }

        @Test
        internal fun admin_no_groups_on_repository_scope_pull_namespace_username() {
            setScope(SCOPE_REPO_NAMESPACE_PULL)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME)
            assertContainsOneAccessItemWithActions(ACTION_PULL)
        }

        @Test
        internal fun admin_no_groups_on_repository_scope_push_namespace_username() {
            setScope(SCOPE_REPO_NAMESPACE_PUSH)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME)
            assertContainsOneAccessItemWithActions(ACTION_PUSH)
        }

        @Test
        internal fun admin_no_groups_on_repository_scope_delete_namespace_username() {
            setScope(SCOPE_REPO_NAMESPACE_DELETE)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME)
            assertContainsOneAccessItemWithActions(ACTION_DELETE)
        }

        @Test
        internal fun admin_no_groups_on_repository_scope_pull_push_namespace_username() {
            setScope(SCOPE_REPO_NAMESPACE_PULL_PUSH)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME)
            assertContainsOneAccessItemWithActions(ACTION_PULL, ACTION_PUSH)
        }
    }

    @Nested
    inner class NamespaceRepositoryOtherGroupsWithUsernameScopeTests {
        @Test
        internal fun admin_other_groups_on_repository_scope_all_namespace_username() {
            setGroups(GROUP_NAMESPACE_OTHER)
            setScope(SCOPE_REPO_NAMESPACE_ALL)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME)
            assertContainsOneAccessItemWithActions(ACTION_ALL)
        }

        @Test
        internal fun admin_other_groups_on_repository_scope_pull_namespace_username() {
            setGroups(GROUP_NAMESPACE_OTHER)
            setScope(SCOPE_REPO_NAMESPACE_PULL)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME)
            assertContainsOneAccessItemWithActions(ACTION_PULL)
        }

        @Test
        internal fun admin_other_groups_on_repository_scope_push_namespace_username() {
            setGroups(GROUP_NAMESPACE_OTHER)
            setScope(SCOPE_REPO_NAMESPACE_PUSH)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME)
            assertContainsOneAccessItemWithActions(ACTION_PUSH)
        }

        @Test
        internal fun admin_other_groups_on_repository_scope_delete_namespace_username() {
            setGroups(GROUP_NAMESPACE_OTHER)
            setScope(SCOPE_REPO_NAMESPACE_DELETE)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME)
            assertContainsOneAccessItemWithActions(ACTION_DELETE)
        }

        @Test
        internal fun admin_other_groups_on_repository_scope_pull_push_namespace_username() {
            setGroups(GROUP_NAMESPACE_OTHER)
            setScope(SCOPE_REPO_NAMESPACE_PULL_PUSH)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME)
            assertContainsOneAccessItemWithActions(ACTION_PULL, ACTION_PUSH)
        }
    }

    @Nested
    inner class NamespaceRepositoryNamespaceGroupsWithUsernameScopeTests {

        @Test
        internal fun admin_namespace_groups_on_repository_scope_all_namespace_username() {
            setGroups(GROUP_NAMESPACE)
            setScope(SCOPE_REPO_NAMESPACE_ALL)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME)
            assertContainsOneAccessItemWithActions(ACTION_ALL)
        }

        @Test
        internal fun admin_namespace_groups_on_repository_scope_pull_namespace_username() {
            setGroups(GROUP_NAMESPACE)
            setScope(SCOPE_REPO_NAMESPACE_PULL)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME)
            assertContainsOneAccessItemWithActions(ACTION_PULL)
        }

        @Test
        internal fun admin_namespace_groups_on_repository_scope_push_namespace_username() {
            setGroups(GROUP_NAMESPACE)
            setScope(SCOPE_REPO_NAMESPACE_PUSH)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME)
            assertContainsOneAccessItemWithActions(ACTION_PUSH)
        }

        @Test
        internal fun admin_namespace_groups_on_repository_scope_delete_namespace_username() {
            setGroups(GROUP_NAMESPACE)
            setScope(SCOPE_REPO_NAMESPACE_DELETE)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME)
            assertContainsOneAccessItemWithActions(ACTION_DELETE)
        }

        @Test
        internal fun admin_namespace_groups_on_repository_scope_pull_push_namespace_username() {
            setGroups(GROUP_NAMESPACE)
            setScope(SCOPE_REPO_NAMESPACE_PULL_PUSH)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME)
            assertContainsOneAccessItemWithActions(ACTION_PULL, ACTION_PUSH)
        }
    }

    @Nested
    inner class NamespaceRepositoryNoGroupsWithUsernameAndGroupScopeTests {
        @Test
        internal fun admin_no_groups_on_repository_scope_all_namespace_username_and_group() {
            setScope(SCOPE_REPO_NAMESPACE_ALL)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME, NAMESPACE_SCOPE_GROUP)
            assertContainsOneAccessItemWithActions(ACTION_ALL)
        }

        @Test
        internal fun admin_no_groups_on_repository_scope_pull_namespace_username_and_group() {
            setScope(SCOPE_REPO_NAMESPACE_PULL)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME, NAMESPACE_SCOPE_GROUP)
            assertContainsOneAccessItemWithActions(ACTION_PULL)
        }

        @Test
        internal fun admin_no_groups_on_repository_scope_push_namespace_username_and_group() {
            setScope(SCOPE_REPO_NAMESPACE_PUSH)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME, NAMESPACE_SCOPE_GROUP)
            assertContainsOneAccessItemWithActions(ACTION_PUSH)
        }

        @Test
        internal fun admin_no_groups_on_repository_scope_delete_namespace_username_and_group() {
            setScope(SCOPE_REPO_NAMESPACE_DELETE)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME, NAMESPACE_SCOPE_GROUP)
            assertContainsOneAccessItemWithActions(ACTION_DELETE)
        }

        @Test
        internal fun admin_no_groups_on_repository_scope_pull_push_namespace_username_and_group() {
            setScope(SCOPE_REPO_NAMESPACE_PULL_PUSH)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME, NAMESPACE_SCOPE_GROUP)
            assertContainsOneAccessItemWithActions(ACTION_PUSH, ACTION_PULL)
        }
    }

    @Nested
    inner class NamespaceRepositoryOtherGroupsWithUsernameAndGroupScopeTests {
        @Test
        internal fun admin_other_groups_on_repository_scope_all_namespace_username_and_group() {
            setGroups(GROUP_NAMESPACE_OTHER)
            setScope(SCOPE_REPO_NAMESPACE_ALL)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME, NAMESPACE_SCOPE_GROUP)
            assertContainsOneAccessItemWithActions(ACTION_ALL)
        }

        @Test
        internal fun admin_other_groups_on_repository_scope_pull_namespace_username_and_group() {
            setGroups(GROUP_NAMESPACE_OTHER)
            setScope(SCOPE_REPO_NAMESPACE_PULL)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME, NAMESPACE_SCOPE_GROUP)
            assertContainsOneAccessItemWithActions(ACTION_PULL)
        }

        @Test
        internal fun admin_other_groups_on_repository_scope_push_namespace_username_and_group() {
            setGroups(GROUP_NAMESPACE_OTHER)
            setScope(SCOPE_REPO_NAMESPACE_PUSH)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME, NAMESPACE_SCOPE_GROUP)
            assertContainsOneAccessItemWithActions(ACTION_PUSH)
        }

        @Test
        internal fun admin_other_groups_on_repository_scope_delete_namespace_username_and_group() {
            setGroups(GROUP_NAMESPACE_OTHER)
            setScope(SCOPE_REPO_NAMESPACE_DELETE)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME, NAMESPACE_SCOPE_GROUP)
            assertContainsOneAccessItemWithActions(ACTION_DELETE)
        }

        @Test
        internal fun admin_other_groups_on_repository_scope_pull_push_namespace_username_and_group() {
            setGroups(GROUP_NAMESPACE_OTHER)
            setScope(SCOPE_REPO_NAMESPACE_PULL_PUSH)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME, NAMESPACE_SCOPE_GROUP)
            assertContainsOneAccessItemWithActions(ACTION_PULL, ACTION_PUSH)
        }
    }

    @Nested
    inner class NamespaceRepositoryNamespaceGroupsWithUsernameAndGroupScopeTests {

        @Test
        internal fun admin_namespace_groups_on_repository_scope_all_namespace_username_and_group() {
            setGroups(GROUP_NAMESPACE)
            setScope(SCOPE_REPO_NAMESPACE_ALL)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME, NAMESPACE_SCOPE_GROUP)
            assertContainsOneAccessItemWithActions(ACTION_ALL)
        }

        @Test
        internal fun admin_namespace_groups_on_repository_scope_pull_namespace_username_and_group() {
            setGroups(GROUP_NAMESPACE)
            setScope(SCOPE_REPO_NAMESPACE_PULL)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME, NAMESPACE_SCOPE_GROUP)
            assertContainsOneAccessItemWithActions(ACTION_PULL)
        }

        @Test
        internal fun admin_namespace_groups_on_repository_scope_push_namespace_username_and_group() {
            setGroups(GROUP_NAMESPACE)
            setScope(SCOPE_REPO_NAMESPACE_PUSH)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME, NAMESPACE_SCOPE_GROUP)
            assertContainsOneAccessItemWithActions(ACTION_PUSH)
        }

        @Test
        internal fun admin_namespace_groups_on_repository_scope_delete_namespace_username_and_group() {
            setGroups(GROUP_NAMESPACE)
            setScope(SCOPE_REPO_NAMESPACE_DELETE)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME, NAMESPACE_SCOPE_GROUP)
            assertContainsOneAccessItemWithActions(ACTION_DELETE)
        }

        @Test
        internal fun admin_namespace_groups_on_repository_scope_pull_push_namespace_username_and_group() {
            setGroups(GROUP_NAMESPACE)
            setScope(SCOPE_REPO_NAMESPACE_PULL_PUSH)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME, NAMESPACE_SCOPE_GROUP)
            assertContainsOneAccessItemWithActions(ACTION_PULL, ACTION_PUSH)
        }
    }


    @Nested
    inner class DefaultRepositoryPluginNoGroupsTests {

        @Test
        internal fun admin_no_groups_on_repository_plugin_scope_all_default() {
            setScope(SCOPE_REPO_PLUGIN_DEFAULT_ALL)
            assertContainsOneAccessItemWithActions(ACTION_ALL)
        }

        @Test
        internal fun admin_no_groups_on_repository_plugin_scope_pull_default() {
            setScope(SCOPE_REPO_PLUGIN_DEFAULT_PULL)
            assertContainsOneAccessItemWithActions(ACTION_PULL)
        }

        @Test
        internal fun admin_no_groups_on_repository_plugin_scope_push_default() {
            setScope(SCOPE_REPO_PLUGIN_DEFAULT_PUSH)
            assertContainsOneAccessItemWithActions(ACTION_PUSH)
        }

        @Test
        internal fun admin_no_groups_on_repository_plugin_scope_delete_default() {
            setScope(SCOPE_REPO_PLUGIN_DEFAULT_DELETE)
            assertContainsOneAccessItemWithActions(ACTION_DELETE)
        }

        @Test
        internal fun admin_no_groups_on_repository_plugin_scope_pull_push_default() {
            setScope(SCOPE_REPO_PLUGIN_DEFAULT_PULL_PUSH)
            assertContainsOneAccessItemWithActions(ACTION_PULL, ACTION_PUSH)
        }
    }

    @Nested
    inner class DefaultRepositoryPluginOtherGroupsTests {

        @Test
        internal fun admin_other_groups_on_repository_plugin_scope_all_default() {
            setGroups(GROUP_NAMESPACE_OTHER)
            setScope(SCOPE_REPO_PLUGIN_DEFAULT_ALL)
            assertContainsOneAccessItemWithActions(ACTION_ALL)
        }

        @Test
        internal fun admin_other_groups_on_repository_plugin_scope_pull_default() {
            setGroups(GROUP_NAMESPACE_OTHER)
            setScope(SCOPE_REPO_PLUGIN_DEFAULT_PULL)
            assertContainsOneAccessItemWithActions(ACTION_PULL)
        }

        @Test
        internal fun admin_other_groups_on_repository_plugin_scope_push_default() {
            setGroups(GROUP_NAMESPACE_OTHER)
            setScope(SCOPE_REPO_PLUGIN_DEFAULT_PUSH)
            assertContainsOneAccessItemWithActions(ACTION_PUSH)
        }

        @Test
        internal fun admin_other_groups_on_repository_plugin_scope_delete_default() {
            setGroups(GROUP_NAMESPACE_OTHER)
            setScope(SCOPE_REPO_PLUGIN_DEFAULT_DELETE)
            assertContainsOneAccessItemWithActions(ACTION_DELETE)
        }

        @Test
        internal fun admin_other_groups_on_repository_plugin_scope_pull_push_default() {
            setGroups(GROUP_NAMESPACE_OTHER)
            setScope(SCOPE_REPO_PLUGIN_DEFAULT_PULL_PUSH)
            assertContainsOneAccessItemWithActions(ACTION_PULL, ACTION_PUSH)
        }
    }

    @Nested
    inner class DefaultRepositoryPluginNamespaceGroupsTests {

        @Test
        internal fun admin_namespace_groups_on_repository_plugin_scope_all_default() {
            setGroups(GROUP_NAMESPACE)
            setScope(SCOPE_REPO_PLUGIN_DEFAULT_ALL)
            assertContainsOneAccessItemWithActions(ACTION_ALL)
        }

        @Test
        internal fun admin_namespace_groups_on_repository_plugin_scope_pull_default() {
            setGroups(GROUP_NAMESPACE)
            setScope(SCOPE_REPO_PLUGIN_DEFAULT_PULL)
            assertContainsOneAccessItemWithActions(ACTION_PULL)
        }

        @Test
        internal fun admin_namespace_groups_on_repository_plugin_scope_push_default() {
            setGroups(GROUP_NAMESPACE)
            setScope(SCOPE_REPO_PLUGIN_DEFAULT_PUSH)
            assertContainsOneAccessItemWithActions(ACTION_PUSH)
        }

        @Test
        internal fun admin_namespace_groups_on_repository_plugin_scope_delete_default() {
            setGroups(GROUP_NAMESPACE)
            setScope(SCOPE_REPO_PLUGIN_DEFAULT_DELETE)
            assertContainsOneAccessItemWithActions(ACTION_DELETE)
        }


        @Test
        internal fun admin_namespace_groups_on_repository_plugin_scope_pull_push_default() {
            setGroups(GROUP_NAMESPACE)
            setScope(SCOPE_REPO_PLUGIN_DEFAULT_PULL_PUSH)
            assertContainsOneAccessItemWithActions(ACTION_PULL, ACTION_PUSH)
        }
    }

    @Nested
    inner class NamespaceRepositoryPluginNoGroupsTests {

        @Test
        internal fun admin_no_groups_on_repository_plugin_scope_all_namespace() {
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_ALL)
            assertContainsOneAccessItemWithActions(ACTION_ALL)
        }

        @Test
        internal fun admin_no_groups_on_repository_plugin_scope_pull_namespace() {
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_PULL)
            assertContainsOneAccessItemWithActions(ACTION_PULL)
        }

        @Test
        internal fun admin_no_groups_on_repository_plugin_scope_push_namespace() {
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_PUSH)
            assertContainsOneAccessItemWithActions(ACTION_PUSH)
        }

        @Test
        internal fun admin_no_groups_on_repository_plugin_scope_delete_namespace() {
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_DELETE)
            assertContainsOneAccessItemWithActions(ACTION_DELETE)
        }

        @Test
        internal fun admin_no_groups_on_repository_plugin_scope_pull_push_namespace() {
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_PULL_PUSH)
            assertContainsOneAccessItemWithActions(ACTION_PULL, ACTION_PUSH)
        }
    }

    @Nested
    inner class NamespaceRepositoryPluginOtherGroupsTests {

        @Test
        internal fun admin_other_groups_on_repository_plugin_scope_all_namespace() {
            setGroups(GROUP_NAMESPACE_OTHER)
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_ALL)
            assertContainsOneAccessItemWithActions(ACTION_ALL)
        }

        @Test
        internal fun admin_other_groups_on_repository_plugin_scope_pull_namespace() {
            setGroups(GROUP_NAMESPACE_OTHER)
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_PULL)
            assertContainsOneAccessItemWithActions(ACTION_PULL)
        }

        @Test
        internal fun admin_other_groups_on_repository_plugin_scope_push_namespace() {
            setGroups(GROUP_NAMESPACE_OTHER)
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_PUSH)
            assertContainsOneAccessItemWithActions(ACTION_PUSH)
        }

        @Test
        internal fun admin_other_groups_on_repository_plugin_scope_delete_namespace() {
            setGroups(GROUP_NAMESPACE_OTHER)
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_DELETE)
            assertContainsOneAccessItemWithActions(ACTION_DELETE)
        }


        @Test
        internal fun admin_other_groups_on_repository_plugin_scope_pull_push_namespace() {
            setGroups(GROUP_NAMESPACE_OTHER)
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_PULL_PUSH)
            assertContainsOneAccessItemWithActions(ACTION_PULL, ACTION_PUSH)
        }
    }

    @Nested
    inner class NamespaceRepositoryPluginNamespaceGroupsTests {

        @Test
        internal fun admin_namespace_groups_on_repository_plugin_scope_all_namespace() {
            setGroups(GROUP_NAMESPACE)
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_ALL)
            assertContainsOneAccessItemWithActions(ACTION_ALL)
        }

        @Test
        internal fun admin_namespace_groups_on_repository_plugin_scope_pull_namespace() {
            setGroups(GROUP_NAMESPACE)
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_PULL)
            assertContainsOneAccessItemWithActions(ACTION_PULL)
        }

        @Test
        internal fun admin_namespace_groups_on_repository_plugin_scope_push_namespace() {
            setGroups(GROUP_NAMESPACE)
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_PUSH)
            assertContainsOneAccessItemWithActions(ACTION_PUSH)
        }

        @Test
        internal fun admin_namespace_groups_on_repository_plugin_scope_delete_namespace() {
            setGroups(GROUP_NAMESPACE)
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_DELETE)
            assertContainsOneAccessItemWithActions(ACTION_DELETE)
        }

        @Test
        internal fun admin_namespace_groups_on_repository_plugin_scope_pull_push_namespace() {
            setGroups(GROUP_NAMESPACE)
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_PULL_PUSH)
            assertContainsOneAccessItemWithActions(ACTION_PULL, ACTION_PUSH)
        }
    }

    @Nested
    inner class NamespaceRepositoryPluginNoGroupsWithUsernameScopeTests {

        @Test
        internal fun admin_no_groups_on_repository_plugin_scope_all_namespace_username() {
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_ALL)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME)
            assertContainsOneAccessItemWithActions(ACTION_ALL)
        }

        @Test
        internal fun admin_no_groups_on_repository_plugin_scope_pull_namespace_username() {
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_PULL)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME)
            assertContainsOneAccessItemWithActions(ACTION_PULL)
        }

        @Test
        internal fun admin_no_groups_on_repository_plugin_scope_push_namespace_username() {
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_PUSH)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME)
            assertContainsOneAccessItemWithActions(ACTION_PUSH)
        }

        @Test
        internal fun admin_no_groups_on_repository_plugin_scope_delete_namespace_username() {
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_DELETE)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME)
            assertContainsOneAccessItemWithActions(ACTION_DELETE)
        }

        @Test
        internal fun admin_no_groups_on_repository_plugin_scope_pull_push_namespace_username() {
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_PULL_PUSH)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME)
            assertContainsOneAccessItemWithActions(ACTION_PULL, ACTION_PUSH)
        }
    }

    @Nested
    inner class NamespaceRepositoryPluginOtherGroupsWithUsernameScopeTests {

        @Test
        internal fun admin_other_groups_on_repository_plugin_scope_all_namespace_username() {
            setGroups(GROUP_NAMESPACE_OTHER)
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_ALL)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME)
            assertContainsOneAccessItemWithActions(ACTION_ALL)
        }

        @Test
        internal fun admin_other_groups_on_repository_plugin_scope_pull_namespace_username() {
            setGroups(GROUP_NAMESPACE_OTHER)
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_PULL)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME)
            assertContainsOneAccessItemWithActions(ACTION_PULL)
        }

        @Test
        internal fun admin_other_groups_on_repository_plugin_scope_push_namespace_username() {
            setGroups(GROUP_NAMESPACE_OTHER)
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_PUSH)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME)
            assertContainsOneAccessItemWithActions(ACTION_PUSH)
        }

        @Test
        internal fun admin_other_groups_on_repository_plugin_scope_delete_namespace_username() {
            setGroups(GROUP_NAMESPACE_OTHER)
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_DELETE)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME)
            assertContainsOneAccessItemWithActions(ACTION_DELETE)
        }


        @Test
        internal fun admin_other_groups_on_repository_plugin_scope_pull_push_namespace_username() {
            setGroups(GROUP_NAMESPACE_OTHER)
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_PULL_PUSH)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME)
            assertContainsOneAccessItemWithActions(ACTION_PULL, ACTION_PUSH)
        }
    }

    @Nested
    inner class NamespaceRepositoryPluginNamespaceGroupsWithUsernameScopeTests {

        @Test
        internal fun admin_namespace_groups_on_repository_plugin_scope_all_namespace_username() {
            setGroups(GROUP_NAMESPACE)
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_ALL)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME)
            assertContainsOneAccessItemWithActions(ACTION_ALL)
        }

        @Test
        internal fun admin_namespace_groups_on_repository_plugin_scope_pull_namespace_username() {
            setGroups(GROUP_NAMESPACE)
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_PULL)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME)
            assertContainsOneAccessItemWithActions(ACTION_PULL)
        }

        @Test
        internal fun admin_namespace_groups_on_repository_plugin_scope_push_namespace_username() {
            setGroups(GROUP_NAMESPACE)
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_PUSH)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME)
            assertContainsOneAccessItemWithActions(ACTION_PUSH)
        }

        @Test
        internal fun admin_namespace_groups_on_repository_plugin_scope_delete_namespace_username() {
            setGroups(GROUP_NAMESPACE)
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_DELETE)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME)
            assertContainsOneAccessItemWithActions(ACTION_DELETE)
        }

        @Test
        internal fun admin_namespace_groups_on_repository_plugin_scope_pull_push_namespace_username() {
            setGroups(GROUP_NAMESPACE)
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_PULL_PUSH)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME)
            assertContainsOneAccessItemWithActions(ACTION_PULL, ACTION_PUSH)
        }
    }

    @Nested
    inner class NamespaceRepositoryPluginNoGroupsWithUsernameAndGroupScopeTests {

        @Test
        internal fun admin_no_groups_on_repository_plugin_scope_all_namespace_username_group() {
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_ALL)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME, NAMESPACE_SCOPE_GROUP)
            assertContainsOneAccessItemWithActions(ACTION_ALL)
        }

        @Test
        internal fun admin_no_groups_on_repository_plugin_scope_pull_namespace_username_group() {
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_PULL)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME, NAMESPACE_SCOPE_GROUP)
            assertContainsOneAccessItemWithActions(ACTION_PULL)
        }

        @Test
        internal fun admin_no_groups_on_repository_plugin_scope_push_namespace_username_group() {
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_PUSH)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME, NAMESPACE_SCOPE_GROUP)
            assertContainsOneAccessItemWithActions(ACTION_PUSH)
        }

        @Test
        internal fun admin_no_groups_on_repository_plugin_scope_delete_namespace_username_group() {
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_DELETE)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME, NAMESPACE_SCOPE_GROUP)
            assertContainsOneAccessItemWithActions(ACTION_DELETE)
        }

        @Test
        internal fun admin_no_groups_on_repository_plugin_scope_pull_push_namespace_username_group() {
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_PULL_PUSH)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME, NAMESPACE_SCOPE_GROUP)
            assertContainsOneAccessItemWithActions(ACTION_PULL, ACTION_PUSH)
        }
    }

    @Nested
    inner class NamespaceRepositoryPluginOtherGroupsWithUsernameAndGroupScopeTests {

        @Test
        internal fun admin_other_groups_on_repository_plugin_scope_all_namespace_username_group() {
            setGroups(GROUP_NAMESPACE_OTHER)
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_ALL)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME, NAMESPACE_SCOPE_GROUP)
            assertContainsOneAccessItemWithActions(ACTION_ALL)
        }

        @Test
        internal fun admin_other_groups_on_repository_plugin_scope_pull_namespace_username_group() {
            setGroups(GROUP_NAMESPACE_OTHER)
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_PULL)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME, NAMESPACE_SCOPE_GROUP)
            assertContainsOneAccessItemWithActions(ACTION_PULL)
        }

        @Test
        internal fun admin_other_groups_on_repository_plugin_scope_push_namespace_username_group() {
            setGroups(GROUP_NAMESPACE_OTHER)
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_PUSH)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME, NAMESPACE_SCOPE_GROUP)
            assertContainsOneAccessItemWithActions(ACTION_PUSH)
        }

        @Test
        internal fun admin_other_groups_on_repository_plugin_scope_delete_namespace_username_group() {
            setGroups(GROUP_NAMESPACE_OTHER)
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_DELETE)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME, NAMESPACE_SCOPE_GROUP)
            assertContainsOneAccessItemWithActions(ACTION_DELETE)
        }


        @Test
        internal fun admin_other_groups_on_repository_plugin_scope_pull_push_namespace_username_group() {
            setGroups(GROUP_NAMESPACE_OTHER)
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_PULL_PUSH)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME, NAMESPACE_SCOPE_GROUP)
            assertContainsOneAccessItemWithActions(ACTION_PULL, ACTION_PUSH)
        }
    }

    @Nested
    inner class NamespaceRepositoryPluginNamespaceGroupsWithUsernameAndGroupScopeTests {

        @Test
        internal fun admin_namespace_groups_on_repository_plugin_scope_all_namespace_username_group() {
            setGroups(GROUP_NAMESPACE)
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_ALL)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME, NAMESPACE_SCOPE_GROUP)
            assertContainsOneAccessItemWithActions(ACTION_ALL)
        }

        @Test
        internal fun admin_namespace_groups_on_repository_plugin_scope_pull_namespace_username_group() {
            setGroups(GROUP_NAMESPACE)
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_PULL)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME, NAMESPACE_SCOPE_GROUP)
            assertContainsOneAccessItemWithActions(ACTION_PULL)
        }

        @Test
        internal fun admin_namespace_groups_on_repository_plugin_scope_push_namespace_username_group() {
            setGroups(GROUP_NAMESPACE)
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_PUSH)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME, NAMESPACE_SCOPE_GROUP)
            assertContainsOneAccessItemWithActions(ACTION_PUSH)
        }

        @Test
        internal fun admin_namespace_groups_on_repository_plugin_scope_delete_namespace_username_group() {
            setGroups(GROUP_NAMESPACE)
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_DELETE)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME, NAMESPACE_SCOPE_GROUP)
            assertContainsOneAccessItemWithActions(ACTION_DELETE)
        }

        @Test
        internal fun admin_namespace_groups_on_repository_plugin_scope_pull_push_namespace_username_group() {
            setGroups(GROUP_NAMESPACE)
            setScope(SCOPE_REPO_PLUGIN_NAMESPACE_PULL_PUSH)
            setNamespaceScope(NAMESPACE_SCOPE_USERNAME, NAMESPACE_SCOPE_GROUP)
            assertContainsOneAccessItemWithActions(ACTION_PULL, ACTION_PUSH)
        }
    }

}