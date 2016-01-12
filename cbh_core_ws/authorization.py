from tastypie.authorization import Authorization
from tastypie.exceptions import Unauthorized
import logging
logger = logging.getLogger(__name__)
logger_debug = logging.getLogger(__name__)
from cbh_core_model.models import Project, get_all_project_ids_for_user_perms, get_all_project_ids_for_user, RESTRICTED, get_projects_where_fields_restricted

def viewer_projects(user):
    pids = get_all_project_ids_for_user(user, ["viewer","editor", "admin"])
    return pids

def editor_projects(user):
    pids = get_all_project_ids_for_user(user, ["editor", "admin"])
    return pids

def owner_projects(user):
    pids = get_all_project_ids_for_user(user, ["admin"])
    return pids



class InviteAuthorization(Authorization):

    def login_checks(self, request, model_klass, perms=None):

        if not hasattr(request, 'user'):
            print "no_logged_in_user"
            raise Unauthorized("no_logged_in_user")
        if not request.user.is_authenticated():
            raise Unauthorized("no_logged_in")


    def create_list(self, object_list, bundle):
        return []


    def create_detail(self, object_list, bundle):
        self.login_checks(bundle.request, bundle.obj.__class__)
        pids = editor_projects(bundle.request.user)
        for project in bundle.data["projects_selected"]:
            if(project["id"] not in pids):
                raise Unauthorized("Not authorized to invite to this project, you must have editor status")
        return True


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

    

    def login_checks(self, request, model_klass):
        if not hasattr(request, 'user'):
            print "no_logged_in_user"
            raise Unauthorized("no_logged_in_user")


    def list_checks(self, request, model_klass, object_list):
        perms = request.user.get_all_permissions()
        pids = viewer_projects(request.user)
        self.login_checks(request,  model_klass, )

        return object_list.filter(pk__in=pids)


    def alter_project_data_for_permissions(self, bundle, request):
        edit_projects = editor_projects(request.user)
        own_projects = owner_projects(request.user)
        restricted_and_unrestricted_projects = get_projects_where_fields_restricted(request.user)

        if isinstance(bundle, dict):
            for bun in bundle['objects']:
                bun.data['editor'] = bun.obj.id in edit_projects
                bun.data["owner"] = bun.obj.id in own_projects
                self.alter_bundle_for_user_custom_field_restrictions(bun, restricted_and_unrestricted_projects)
        else:
            bundle.data['editor'] = bundle.obj.id in edit_projects
            bundle.data["owner"] = bundle.obj.id in own_projects






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
        return self.list_checks(bundle.request, bundle.obj.__class__, object_list)


    def update_list(self, object_list, bundle):
        '''Only owners of projects are allowed to update them'''
        return object_list

    def update_detail(self, object_list, bundle):
        '''Only owners of projects are allowed to update them'''
        print "calling"
        return True
        # self.login_checks(bundle.request, bundle.obj.__class__)
        # pids = owner_projects(request.user)
        # if bundle.obj.project.id in pids:
        #     return object_list
        # raise Unauthorized("Not authorized to update project")


    def create_detail(self, object_list, bundle):
        '''All users are allowed to create projects for now'''
        return object_list


class ProjectAuthorization(Authorization):

    """
    Uses permission checking from ``django.contrib.auth`` to map
    ``POST / PUT / DELETE / PATCH`` to their equivalent Django auth
    permissions.

    Both the list & detail variants simply check the model they're based
    on, as that's all the more granular Django's permission setup gets.
    """

    def login_checks(self, request, model_klass, perms=None):
        if not hasattr(request, 'user'):
            print "no_logged_in_user"
            raise Unauthorized("no_logged_in_user")
        if not request.user.is_authenticated():
            raise Unauthorized("no_logged_in")

    def base_checks(self, request, model_klass, data, funct):
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
        pids = funct(request.user)
        if project.id in pids:
            return True
        return False

    def project_ids(self, request ):
        self.login_checks( request, None)
        pids = viewer_projects(request.user)
        return pids

    def create_list(self, object_list, bundle):
        bool = self.base_checks(
            bundle.request, 
            bundle.obj.__class__, 
            bundle.data, 
            edit_projects
            )
        if bool is True:
            return object_list
        else:

            return []

    def read_detail(self, object_list, bundle):

        self.login_checks(bundle.request, bundle.obj.__class__)
        pids = viewer_projects(request.user)
        if bundle.obj.project.id in pids:
            return True
        else:
            raise Unauthorized("not authroized for project")

    def update_list(self, object_list, bundle):
        print "update"

        return []

    def create_detail(self, object_list, bundle):
        self.login_checks(bundle.request, bundle.obj.__class__)
        pids = editor_projects(bundle.request.user)
        if bundle.data["project"].id in pids:
            return True
        else:
            raise Unauthorized("not authroized for project")
        # return self.base_checks(bundle.request, bundle.obj.__class__,
        # bundle.data, ["editor",])

    def update_detail(self, object_list, bundle):
        self.login_checks(bundle.request, bundle.obj.__class__)
        pids = editor_projects(bundle.request.user)
        if bundle.obj.project.id in pids:
            return True

        raise Unauthorized("not authroized for project")

    def read_list(self, object_list, bundle):
        return object_list
