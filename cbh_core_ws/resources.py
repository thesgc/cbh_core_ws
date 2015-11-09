from tastypie.resources import ALL_WITH_RELATIONS
from tastypie.resources import ModelResource
from django.conf import settings
from django.conf.urls import *
from django.http import HttpResponse

from tastypie.resources import ModelResource
from tastypie import fields


from cbh_core_model.models import CustomFieldConfig
from cbh_core_model.models import DataType
from cbh_core_model.models import Project
from cbh_core_model.models import ProjectType
from cbh_core_model.models import SkinningConfig

from cbh_core_ws.authorization import ProjectListAuthorization
from tastypie.authentication import SessionAuthentication
from tastypie.paginator import Paginator
from cbh_core_ws.serializers import CustomFieldsSerializer

from django.db.models import Prefetch


from tastypie.resources import ALL_WITH_RELATIONS
from tastypie.utils.mime import build_content_type
from django.http import HttpResponse
from django.http import HttpResponseRedirect
from django.conf import settings

from django.conf import settings
from django.views.generic import FormView, View
from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth import login as auth_login, logout as auth_logout
from tastypie.resources import ModelResource
from tastypie.authorization import Authorization

# If ``csrf_exempt`` isn't present, stub it.
try:
    from django.views.decorators.csrf import csrf_exempt
except ImportError:
    def csrf_exempt(func):
        return func

try:
    import defusedxml.lxml as lxml
except ImportError:
    lxml = None

try:
    WS_DEBUG = settings.WS_DEBUG
except AttributeError:
    WS_DEBUG = False


from tastypie.authentication import SessionAuthentication

from django.contrib.auth import get_user_model

import inflection


from django.views.generic import TemplateView


def get_field_name_from_key(key):
    return key.replace(u"__space__", u" ")


def get_key_from_field_name(name):
    return name.replace(u" ", u"__space__")


class Index(TemplateView):

    template_name = 'dist/index.html'  # or define get_template_names()

    def get(self, request, *args, **kwargs):
        context = self.get_context_data(**kwargs)
        from django.middleware.csrf import get_token
        csrf_token = get_token(request)
        return self.render_to_response(context)


class UserResource(ModelResource):
    '''Displays information about the User's privileges and personal data'''
    can_view_chemreg = fields.BooleanField(default=True)
    can_view_assayreg = fields.BooleanField(default=True)

    class Meta:
        filtering = {
            "username": ALL_WITH_RELATIONS
        }
        queryset = get_user_model().objects.all()
        resource_name = 'users'
        allowed_methods = ["get", ]
        excludes = ['email', 'password', 'is_active']
        authentication = SessionAuthentication()
        authorization = Authorization()


    def apply_authorization_limits(self, request, object_list):
        return object_list.get(pk=request.user.id)

    def get_object_list(self, request):
        # return super(UserResource,
        # self).get_object_list(request).filter(pk=request.user.id)
        return super(UserResource, self).get_object_list(request)

    def get_permissions():
        """Placeholder for permissions service"""

    def dehydrate_can_view_chemreg(self, bundle):
        '''The _can_see.no_chemreg role in the Django admin is used to
        deny access to chemreg. As superusers have all permissions  by 
        default they would be denied access therefore we check for superuser status and allow access'''
        if bundle.obj.is_superuser:
            return True
        perms = bundle.obj.get_all_permissions()
        if "_can_see.no_chemreg" in perms:
            return False
        return True

    def dehydrate_can_view_assayreg(self, bundle):
        '''The _can_see.no_assayreg role in the Django admin is used to
        deny access to assayreg. As superusers have all permissions  by 
        default they would be denied access therefore we check for superuser status and allow access'''

        if bundle.obj.is_superuser:
            return True
        perms = bundle.obj.get_all_permissions()
        if "_can_see.no_assayreg" in perms:
            return False
        return True

#-------------------------------------------------------------------------


class Login(FormView):
    form_class = AuthenticationForm
    template_name = "cbh_chembl_ws_extension/login.html"
    logout = None

    def get(self, request, *args, **kwargs):

        from django.middleware.csrf import get_token
        csrf_token = get_token(request)
        context = self.get_context_data(
            form=self.get_form(self.get_form_class()))
        redirect_to = settings.LOGIN_REDIRECT_URL
        '''Borrowed from django base detail view'''

        if "django_webauth" in settings.INSTALLED_APPS:
            context["webauth_login"] = True
            username = request.META.get('REMOTE_USER', None)
            if not username:
                # Here we check if this was a redirect after logout in which
                # case we show the button to log out of webauth entirely
                username = request.META.get('HTTP_X_WEBAUTH_USER', None)
            if username:
                context["logout"] = True
        else:
            context["password_login"] = True

        if request.user.is_authenticated():
            return HttpResponseRedirect(redirect_to)
        return self.render_to_response(context)

    def form_valid(self, form):
        redirect_to = settings.LOGIN_REDIRECT_URL
        auth_login(self.request, form.get_user())
        if self.request.session.test_cookie_worked():
            self.request.session.delete_test_cookie()
        # return self.render_to_response(self.get_context_data())
        return HttpResponseRedirect(redirect_to)

    def form_invalid(self, form):
        return self.render_to_response(self.get_context_data(form=form))

    # def dispatch(self, request, *args, **kwargs):
    #     request.session.set_test_cookie()
    #     return super(Login, self).dispatch(request, *args, **kwargs)


class Logout(View):

    def get(self, request, *args, **kwargs):
        auth_logout(request)
        return HttpResponseRedirect(settings.LOGOUT_REDIRECT_URL)


def build_content_type(format, encoding='utf-8'):
    """
    Appends character encoding to the provided format if not already present.
    """
    if 'charset' in format:
        return format

    return "%s; charset=%s" % (format, encoding)


class SkinningResource(ModelResource):

    '''URL resourcing for pulling out sitewide skinning config '''
    class Meta:
        always_return_data = True
        queryset = SkinningConfig.objects.all()
        resource_name = 'cbh_skinning'
        #authorization = Authorization()
        include_resource_uri = False
        allowed_methods = ['get', 'post', 'put']
        default_format = 'application/json'
        authentication = SessionAuthentication()


class ProjectTypeResource(ModelResource):

    '''Resource for Project Type, specifies whether this is a chemical/inventory instance etc '''
    class Meta:
        always_return_data = True
        queryset = ProjectType.objects.all()
        resource_name = 'cbh_project_types'
        #authorization = Authorization()
        include_resource_uri = False
        allowed_methods = ['get', 'post', 'put']
        default_format = 'application/json'
        authentication = SessionAuthentication()


class CustomFieldConfigResource(ModelResource):

    '''Resource for Custom Field Config '''
    class Meta:
        always_return_data = True
        queryset = CustomFieldConfig.objects.all()
        resource_name = 'cbh_custom_field_configs'
        #authorization = ProjectListAuthorization()
        include_resource_uri = False
        allowed_methods = ['get', 'post', 'put']
        default_format = 'application/json'
        authentication = SessionAuthentication()
        filtering = {
            "name": ALL_WITH_RELATIONS
        }


class DataTypeResource(ModelResource):

    '''Resource for data types'''
    plural = fields.CharField(null=True)

    class Meta:
        always_return_data = True
        queryset = DataType.objects.all()
        resource_name = 'cbh_data_types'
        #authorization = ProjectListAuthorization()
        include_resource_uri = False
        allowed_methods = ['get', 'post', 'put']
        default_format = 'application/json'
        authentication = SessionAuthentication()
        filtering = {
            "name": ALL_WITH_RELATIONS
        }
        authorization = Authorization()

    def dehydrate_plural(self, bundle):
        return inflection.pluralize(bundle.obj.name)


class CoreProjectResource(ModelResource):
    project_type = fields.ForeignKey(
        ProjectTypeResource, 'project_type', blank=False, null=False, full=True)
    custom_field_config = fields.ForeignKey(
        CustomFieldConfigResource, 'custom_field_config', blank=False, null=True, full=True)

    class Meta:
        queryset = Project.objects.all()
        authentication = SessionAuthentication()
        paginator_class = Paginator
        allowed_methods = ['get']
        resource_name = 'cbh_projects'
        authorization = ProjectListAuthorization()
        include_resource_uri = False
        default_format = 'application/json'
        #serializer = Serializer()
        serializer = CustomFieldsSerializer()
        filtering = {

            "project_key": ALL_WITH_RELATIONS,
        }

    def get_object_list(self, request):
        return super(CoreProjectResource, self).get_object_list(request).prefetch_related(Prefetch("project_type")).order_by('-modified')

    def alter_list_data_to_serialize(self, request, bundle):
        '''Here we append a list of tags to the data of the GET request if the
        search fields are required'''
        userres = UserResource()
        userbundle = userres.build_bundle(obj=request.user, request=request)
        userbundle = userres.full_dehydrate(userbundle)
        bundle['user'] = userbundle.data

    def create_response(self, request, data, response_class=HttpResponse, **response_kwargs):
        """
        Extracts the common "which-format/serialize/return-response" cycle.
        Mostly a useful shortcut/hook.
        """

        desired_format = self.determine_format(request)
        serialized = self.serialize(request, data, desired_format)
        rc = response_class(content=serialized, content_type=build_content_type(
            desired_format), **response_kwargs)

        if(desired_format == 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'):
            rc['Content-Disposition'] = 'attachment; filename=project_data_explanation.xlsx'
        return rc

    #     editor_projects = self._meta.authorization.editor_projects(request)
    #     for bun in bundle["objects"]:
    #         bun.data["editor"] = bun.obj.id in editor_projects

    #     if request.GET.get("schemaform", None):
    #         searchfields = set([])
    #         searchfield_items = []

    #         for bun in bundle["objects"]:
    #             schemaform = self.get_schema_form(bun.obj.custom_field_config,
    #                 bun.obj.project_key,
    #                 searchfield_items=searchfield_items,
    #                 searchfields=searchfields,)
    #             bun.data["schemaform"] = schemaform
    #             bun.data["editor"] = bun.obj.id in editor_projects

    # if(self.determine_format(request) ==
    # 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' or
    # request.GET.get("format") == "xls"  ):

    #         cfr_string = self.get_object_list(request).filter(id=request.GET.get("project_key"))[0].custom_field_config.schemaform
    #         cfr_json = json.loads(cfr_string)
    #         bundle['custom_field_config'] = cfr_json['form']

    #     return bundle

    # def get_schema_form(self, custom_field_config, project_key, searchfield_items=[], searchfields=set([]),):
    #     fields = []

    #     for f in custom_field_config.pinned_custom_field.all():
    #         d = self.get_field_values(f, project_key)
    #         fields.append(d)
    #         for item in d[4]:
    #             if item["value"] not in searchfields:
    #                 searchfields.add(item["value"] )
    #                 searchfield_items.append(item)
    #     schemaform = {
    #             "schema" :{
    #                         "type" : "object",
    #                         "properties"   :  dict((field[0],field[1]) for field in fields),
    #                         "required" : []
    #             },
    #             "form" : [field[0] if not field[3] else field[3] for field in fields ]
    #         }
    #     return schemaform

    # def get_field_values(self,  obj, projectKey):
    #     data =  copy.deepcopy(obj.FIELD_TYPE_CHOICES[obj.field_type]["data"])

    #     data["title"] = obj.name
    #     data["placeholder"] = obj.description
    #     data["friendly_field_type"] = obj.FIELD_TYPE_CHOICES[obj.field_type]["name"]

    #     form = {}
    #     form["field_type"] = obj.field_type
    #     form["position"] = obj.position
    #     form["key"] = obj.name
    #     form["title"] = obj.name
    #     form["placeholder"] = obj.description
    #     form["allowed_values"] = obj.allowed_values
    #     form["part_of_blinded_key"] = obj.part_of_blinded_key
    #     searchitems = []
    #     if obj.UISELECT in data.get("format", ""):
    #         allowed_items = obj.get_allowed_items(projectKey)
    #         data["items"] = allowed_items[0]
    #         searchitems = allowed_items[1]
    #         #if we have a uiselect field with no description, make the placeholder say "Choose..."
    #         #if obj.description == None:
    #         form["placeholder"] = "Choose..."
    #         form["help"] = obj.description
    #         # form["helpdirectivename"] = "info-box"
    #         # form["helpdirectiveparams"] = "freetext='%s'" % (obj.description)
    #         # form["helpDirectiveClasses"] = "pull-right info-box"
    #         # #form["title"] = "%s<info-box freetext='%s'></info-box>" % (obj.name, obj.description)
    #     else:
    #         allowed_items = obj.get_allowed_items(projectKey)
    #         searchitems = allowed_items[1]

    #     maxdate = time.strftime("%Y-%m-%d")
    #     if data.get("format", False) == obj.DATE:
    #         form.update( {
    #             "minDate": "2000-01-01",
    #             "maxDate": maxdate,
    #             'type': 'datepicker',
    #             "format": "yyyy-mm-dd",
    #             'pickadate': {
    #               'selectYears': True,
    #               'selectMonths': True,
    #             },
    #         })

    #     else:
    #         for item in ["options"]:
    #             stuff = data.pop(item, None)
    #             if stuff:
    #                 form[item] = stuff
    #     return (obj.name, data, obj.required, form, searchitems)

    # def create_response(self, request, data, response_class=HttpResponse, **response_kwargs):
    #     """
    #     Extracts the common "which-format/serialize/return-response" cycle.
    #     Mostly a useful shortcut/hook.
    #     """

    #     desired_format = self.determine_format(request)
    #     serialized = self.serialize(request, data, desired_format)
    #     rc = response_class(content=serialized, content_type=build_content_type(desired_format), **response_kwargs)

    #     if(desired_format == 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'):
    #         rc['Content-Disposition'] = 'attachment; filename=project_data_explanation.xlsx'
    #     return rc
