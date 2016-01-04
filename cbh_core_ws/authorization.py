from tastypie.authorization import Authorization
from tastypie.exceptions import Unauthorized
import logging
logger = logging.getLogger(__name__)
logger_debug = logging.getLogger(__name__)
from cbh_core_model.models import Project, get_all_project_ids_for_user_perms, get_all_project_ids_for_user, RESTRICTED, get_projects_where_fields_restricted






class InviteAuthorization(Authorization):

    def login_checks(self, request, model_klass, perms=None):

        # If it doesn't look like a model, we can't check permissions.
        # if not model_klass or not getattr(model_klass, '_meta', None):
        #     print "improper_setup_of_authorization"
        #     raise Unauthorized("improper_setup_of_authorization")
        # User must be logged in to check permissions.
        if not hasattr(request, 'user'):
            print "no_logged_in_user"
            raise Unauthorized("no_logged_in_user")
        if not request.user.is_authenticated():
            raise Unauthorized("no_logged_in")


    def create_list(self, object_list, bundle):
        return []


    def create_detail(self, object_list, bundle):
        self.login_checks(bundle.request, bundle.obj.__class__)
        pids = get_all_project_ids_for_user_perms(
            bundle.request.user.get_all_permissions(), ["editor", ])
        for project in bundle.data["projects_selected"]:
            if(project["id"] not in pids):
                raise Unauthorized("Not authorized to invite to this project, you must have editor status")
        return True
        # return self.base_checks(bundle.request, bundle.obj.__class__,
        # bundle.data, ["editor",])

    def update_detail(self, object_list, bundle):

        raise Unauthorized("not authroized for to update")







class ProjectListAuthorization(Authorization):

    """
    Uses permission checking from ``django.contrib.auth`` to map
    ``POST / PUT / DELETE / PATCH`` to their equivalent Django auth
    permissions.

    Both the list & detail variants simply check the model they're based
    on, as that's all the more granular Django's permission setup gets.
    """

    def editor_projects(self, request, ):
        pids = get_all_project_ids_for_user(request.user, ["editor"])
        return pids

    def login_checks(self, request, model_klass):

        # If it doesn't look like a model, we can't check permissions.
        # if not model_klass or not getattr(model_klass, '_meta', None):
        #     print "improper_setup_of_authorization"
        #     raise Unauthorized("improper_setup_of_authorization")
        # User must be logged in to check permissions.
        if not hasattr(request, 'user'):
            print "no_logged_in_user"
            raise Unauthorized("no_logged_in_user")

    def base_checks(self, request, model_klass, data, possible_perm_levels, perms=None):
        self.login_checks(request, model_klass)
        if not data.get("project_key", None):
            print "no_project_key"
            raise Unauthorized("no_project_key")

        project = data.get("project", False)

        has_perm = Project.objects.get_user_permission(
            project.id, request.user, possible_perm_levels, perms=perms)
        if has_perm is True:
            return True

        print "user_does_not_have_correct_permissions_for_operation"
        raise Unauthorized(
            "user_does_not_have_correct_permissions_for_operation")

    def list_checks(self, request, model_klass, data, possible_perm_levels, object_list):
        perms = request.user.get_all_permissions()
        logger.info(perms)
        pids = get_all_project_ids_for_user_perms(perms, possible_perm_levels)
        logger.info(pids)
        self.login_checks(request,  model_klass, )

        return object_list.filter(pk__in=pids)


    def alter_project_data_for_permissions(self, bundle, request):
        editor_projects = self.editor_projects(request)
        restricted_and_unrestricted_projects = get_projects_where_fields_restricted(request.user)

        if bundle.get("objects", False):
            for bun in bundle['objects']:
                bun.data['editor'] = bun.obj.id in editor_projects
                self.alter_bundle_for_user_custom_field_restrictions(bun, restricted_and_unrestricted_projects)
        else:
            bundle['editor'] = bundle.obj.id in editor_projects
            self.alter_bundle_for_user_custom_field_restrictions(bundle, restricted_and_unrestricted_projects)

    def alter_bundle_for_user_custom_field_restrictions(self, bundle, restricted_and_unrestricted_projects):
        """Post serialization modification to the list of fields based on the field permissions"""
        if bundle.data["id"] in restricted_and_unrestricted_projects[RESTRICTED]:
            new_fields = []
            for field in bundle.data["custom_field_config"].data["project_data_fields"]:
                if field.data["open_or_restricted"] == RESTRICTED:
                    #This is a restricted field and the user's access is restricted therefore block them
                    pass
                else:
                    new_fields.append(field)
            bundle.data["custom_field_config"].data["project_data_fields"] = new_fields


    def read_list(self, object_list, bundle):
        return self.list_checks(bundle.request, bundle.obj.__class__, bundle.data, ["editor", "viewer", ], object_list)


class ProjectAuthorization(Authorization):

    """
    Uses permission checking from ``django.contrib.auth`` to map
    ``POST / PUT / DELETE / PATCH`` to their equivalent Django auth
    permissions.

    Both the list & detail variants simply check the model they're based
    on, as that's all the more granular Django's permission setup gets.
    """

    def login_checks(self, request, model_klass, perms=None):

        # If it doesn't look like a model, we can't check permissions.
        # if not model_klass or not getattr(model_klass, '_meta', None):
        #     print "improper_setup_of_authorization"
        #     raise Unauthorized("improper_setup_of_authorization")
        # User must be logged in to check permissions.
        if not hasattr(request, 'user'):
            print "no_logged_in_user"
            raise Unauthorized("no_logged_in_user")
        if not request.user.is_authenticated():
            raise Unauthorized("no_logged_in")

    def base_checks(self, request, model_klass, data, possible_perm_levels):
        self.login_checks(request, model_klass)

        if not data.get("project__project_key", None):
            if not data.get("project_key"):
                if not data.get("projectKey"):
                    try:
                        key = data.project.project_key
                    except:

                        print "no_project_key"
                        raise Unauthorized("no_project_key")
                else:
                    key = data.get("projectKey")
            else:
                key = data.get("project_key")
        else:
            key = data.get("project__project_key")

        project = Project.objects.get(project_key=key)
        pids = get_all_project_ids_for_user_perms(
            request.user.get_all_permissions(), possible_perm_levels)
        if project.id in pids:
            return True
        return False

    def project_ids(self, request ):
        self.login_checks( request, None)
        pids = get_all_project_ids_for_user_perms(
            request.user.get_all_permissions(), ["editor", "viewer", ])
        return pids

    def create_list(self, object_list, bundle):
        print "create"
        bool = self.base_checks(
            bundle.request, bundle.obj.__class__, bundle.data, ["editor", ])
        if bool is True:
            return object_list
        else:

            return []

    def read_detail(self, object_list, bundle):
        print "readdet"

        self.login_checks(bundle.request, bundle.obj.__class__)
        pids = get_all_project_ids_for_user_perms(
            bundle.request.user.get_all_permissions(), ["editor", "viewer"])
        if bundle.obj.project.id in pids:
            return True
        else:
            raise Unauthorized("not authroized for project")

    def update_list(self, object_list, bundle):
        print "update"

        return []

    def create_detail(self, object_list, bundle):
        self.login_checks(bundle.request, bundle.obj.__class__)
        pids = get_all_project_ids_for_user_perms(
            bundle.request.user.get_all_permissions(), ["editor", ])
        if bundle.data["project"].id in pids:
            return True
        else:
            raise Unauthorized("not authroized for project")
        # return self.base_checks(bundle.request, bundle.obj.__class__,
        # bundle.data, ["editor",])

    def update_detail(self, object_list, bundle):
        self.login_checks(bundle.request, bundle.obj.__class__)
        pids = get_all_project_ids_for_user_perms(
            bundle.request.user.get_all_permissions(), ["editor", ])
        if bundle.obj.project.id in pids:
            return True

        raise Unauthorized("not authroized for project")

    def read_list(self, object_list, bundle):
        return object_list
