import logging

# Get an instance of a logger
logger = logging.getLogger(__name__)


from django.test import RequestFactory
from tastypie.resources import ALL_WITH_RELATIONS
from tastypie.resources import ModelResource
from tastypie.exceptions import BadRequest
from django.conf import settings
from django.conf.urls import *
from django.http import HttpResponse, QueryDict
import shortuuid
from tastypie.resources import ModelResource
from tastypie import fields
from django.contrib.auth.tokens import default_token_generator
from tastypie.exceptions import ImmediateHttpResponse

from django.contrib.auth.forms import PasswordResetForm
from cbh_core_model.models import CustomFieldConfig
from cbh_core_model.models import DataType
from cbh_core_model.models import Project
from cbh_core_model.models import ProjectType
from cbh_core_model.models import SkinningConfig
from cbh_core_model.models import Invitation

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
from cbh_core_ws.authorization import get_all_project_ids_for_user
from django.conf import settings
from django.views.generic import FormView, View
from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth import login as auth_login, logout as auth_logout
from tastypie.resources import ModelResource
from tastypie.authorization import Authorization
from tastypie import http
from django.contrib.auth.views import password_reset
from django.db import IntegrityError
# If ``csrf_exempt`` isn't present, stub it.
try:
    from django.views.decorators.csrf import csrf_exempt
except ImportError:
    def csrf_exempt(func):
        return func
from  BeautifulSoup import BeautifulSoup
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
import six
import importlib

from django.views.generic import TemplateView
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from django.contrib.auth.forms import PasswordResetForm, loader, get_current_site, urlsafe_base64_encode, force_bytes

from urllib import urlencode
from django.core.mail import EmailMessage



class CSRFExemptMixin(object):
    @method_decorator(csrf_exempt)
    def dispatch(self, *args, **kwargs):
        return super(CSRFExemptMixin, self).dispatch(*args, **kwargs)

def get_field_name_from_key(key):
    return key.replace(u"__space__", u" ")


def get_key_from_field_name(name):
    return name.replace(u" ", u"__space__")


from django.middleware.csrf import get_token


class SimpleResourceURIField(fields.ApiField):

    """
    Provide just the id field as a resource URI
    """
    dehydrated_type = 'string'
    is_related = False
    self_referential = False
    help_text = 'A related resource. Can be either a URI or set of nested resource data.'

    def __init__(self, to, attribute, full=False, related_name=None, default=fields.NOT_PROVIDED, null=False, blank=False, readonly=False,  unique=False, help_text=None, use_in='all'):
        """

        """
        super(SimpleResourceURIField, self).__init__(attribute=attribute, default=default, null=null, blank=blank,
                                                     readonly=readonly, unique=unique, help_text=help_text, use_in=use_in)
        self.related_name = related_name
        self.to = to
        self._to_class = None
        self._rel_resources = {}

        self.api_name = None
        self.resource_name = None

        if self.to == 'self':
            self.self_referential = True



    def contribute_to_class(self, cls, name):
        super(SimpleResourceURIField, self).contribute_to_class(cls, name)

        # Check if we're self-referential and hook it up.
        # We can't do this quite like Django because there's no ``AppCache``
        # here (which I think we should avoid as long as possible).
        if self.self_referential or self.to == 'self':
            self._to_class = cls

    def convert(self, value):
        """
        Handles conversion between the data found and the type of the field.
        Extending classes should override this method and provide correct
        data coercion.
        """
        if value is None:
            return None
        cls = self.to_class()
        resource_uri = cls.get_resource_uri()
        return "%s/%d" % (resource_uri, value)

    def hydrate(self, bundle):
        """
        Takes data stored in the bundle for the field and returns it. Used for
        taking simple data and building a instance object.
        """
        if self.readonly:
            return None
        if self.instance_name not in bundle.data:
            if self.is_related and not self.is_m2m:
                # We've got an FK (or alike field) & a possible parent object.
                # Check for it.
                if bundle.related_obj and bundle.related_name in (self.attribute, self.instance_name):
                    return bundle.related_obj
            if self.blank:
                return None
            if self.attribute:
                try:
                    val = getattr(bundle.obj, self.attribute, None)

                    if val is not None:
                        return val
                except ObjectDoesNotExist:
                    pass
            if self.instance_name:
                try:
                    if hasattr(bundle.obj, self.instance_name):
                        return getattr(bundle.obj, self.instance_name)
                except ObjectDoesNotExist:
                    pass
            if self.has_default():
                if callable(self._default):
                    return self._default()

                return self._default
            if self.null:
                return None

            raise ApiFieldError(
                "The '%s' field has no data and doesn't allow a default or null value." % self.instance_name)
        # New code to rerturn URI
        value = bundle.data[self.instance_name]
        if value is None:
            return value
        if str(value).endswith("/"):
            value = value[:-1]
        data = str(value).split("/")
        
        return int(data[len(data) - 1])
        
    @property
    def to_class(self):
        # We need to be lazy here, because when the metaclass constructs the
        # Resources, other classes may not exist yet.
        # That said, memoize this so we never have to relookup/reimport.
        if self._to_class:
            return self._to_class

        if not isinstance(self.to, six.string_types):
            self._to_class = self.to
            return self._to_class

        # It's a string. Let's figure it out.
        if '.' in self.to:
            # Try to import.
            module_bits = self.to.split('.')
            module_path, class_name = '.'.join(
                module_bits[:-1]), module_bits[-1]
            module = importlib.import_module(module_path)
        else:
            # We've got a bare class name here, which won't work (No AppCache
            # to rely on). Try to throw a useful error.
            raise ImportError(
                "Tastypie requires a Python-style path (<module.module.Class>) to lazy load related resources. Only given '%s'." % self.to)

        self._to_class = getattr(module, class_name, None)

        if self._to_class is None:
            raise ImportError("Module '%s' does not appear to have a class called '%s'." % (
                module_path, class_name))

        return self._to_class




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
        allowed_methods = ["get", "post"]
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

    # def get_invite_user(self, request, **kwargs):
    #     deserialized = self.deserialize(request, request.body, format=request.META.get(
    #         'CONTENT_TYPE', 'application/json'))
    #     bundle = self.build_bundle(
    #         data=dict_strip_unicode_keys(deserialized), request=request)
    #     print(bundle.obj)
    #     return self.create_response(request, bundle, response_class=http.HttpAccepted)


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


class Login( CSRFExemptMixin, FormView):
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


    def post(self, request, *args, **kwargs):
        """
        Handles POST requests, instantiating a form instance with the passed
        POST variables and then checked for validity.
        """
        redirect_to = settings.LOGIN_REDIRECT_URL
        '''Borrowed from django base detail view'''
        from django.middleware.csrf import get_token
        csrf_token = get_token(request)
        if request.user.is_authenticated():
            #The user has pressed back in their browser and therefore should be redirected
            return HttpResponseRedirect(redirect_to)
        form = self.get_form(self.get_form_class())
        if form.is_valid():
            return self.form_valid(form)
        else:
            return self.form_invalid(form)



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



class MyPasswordResetForm(PasswordResetForm):
    def save(self, domain_override=None,
             subject_template_name='registration/password_reset_subject.txt',
             email_template_name='registration/password_reset_email.html',
             use_https=False, token_generator=default_token_generator,
             from_email=None, request=None, html_email_template_name=None, extra_email_context={}, user=None):
        """
        Generates a one-use only link for resetting password and sends to the
        user.
        """
        from django.core.mail import send_mail
        email = self.cleaned_data["email"]
 
        if not domain_override:
            current_site = get_current_site(request)
            site_name = current_site.name
            domain = current_site.domain
        else:
            site_name = domain = domain_override
        c = {
            'email': user.email,
            'domain': domain,
            'site_name': site_name,
            'uid': urlsafe_base64_encode(force_bytes(user.pk)),
            'user': user,
            'token': token_generator.make_token(user),
            'protocol': 'https' if use_https else 'http',
            'extra' : extra_email_context,

        }
        subject = loader.render_to_string(subject_template_name, c)
        # Email subject *must not* contain newlines
        subject = ''.join(subject.splitlines())
        html_email = loader.render_to_string(email_template_name, c)
        soup = BeautifulSoup(html_email)
        email = soup.getText()

        
        send_mail(subject, email, from_email, [user.email], html_message=html_email, fail_silently=False)

 

class InvitationResource(ModelResource):
    '''Resource for Invitation model. This will setup creation of the invite email and new user '''

    created_by = fields.ForeignKey(
        "cbh_core_ws.resources.UserResource", 'created_by', full=True)
    class Meta:
        queryset = Invitation.objects.all()
        resource_name = 'invitations'
        authorization = Authorization()
        include_resource_uri = False
        allowed_methods = ['get', 'post', 'put']
        default_format = 'application/json'
        authentication = SessionAuthentication()
        always_return_data = True
        filtering = {
            "email": ALL_WITH_RELATIONS
        }

    def hydrate_created_by(self, bundle):
        user = get_user_model().objects.get(pk=bundle.request.user.pk)
        bundle.obj.created_by = user
        return bundle



    def get_form(self, email, new_user, data, created, request, email_template_name, subject_template_name):
        server = settings.SERVER_EMAIL
        form = MyPasswordResetForm(QueryDict(urlencode({"email": email})))
        hostname = request.META["HTTP_ORIGIN"]
        if form.is_valid():
            form.users_cache = [new_user,]
            opts = {
                'use_https': request.is_secure(),
                'token_generator': default_token_generator,
                'from_email': server,
                'user' : new_user,
                'email_template_name': email_template_name,
                'subject_template_name': subject_template_name,
                'request': request,
                'extra_email_context': {'hostname':hostname, 'invite': data.data, 'login_url' : settings.LOGIN_URL, },
            }
            form.save(**opts)

        else:
            raise BadRequest("Email not valid")

    def create_response(self, request, data, response_class=HttpResponse, **response_kwargs):
        """
        Extracts the common "which-format/serialize/return-response" cycle.
        Mostly a useful shortcut/hook.
        """
        desired_format = self.determine_format(request)
       

        if response_class == http.HttpCreated:     
            email = data.data["email"]
            if email.endswith("ox.ac.uk"):
                #send via webauth
                raise BadRequest("We do not yet support inviting users at Oxford to projects. This feature will come soon.")
            else:

                UserObj = get_user_model()
                new_user, created = UserObj.objects.get_or_create(email=email, username=email)
                logger.info(data.data)
                for perm in data.data["projects_selected"]:
                    p = Project.objects.get(id=perm["id"])
                    p.make_viewer(new_user)
                    p.save()
                data.data["message"] = "Invite sent successfully to %s, would you like to invite anyone else?" % email
                email_template_name = 'cbh_core_ws/email_new_user.html'
                subject_template_name = 'cbh_core_ws/subject_new_user.html'
                if not created:
                    projects_with_reader_access = get_all_project_ids_for_user(new_user,["editor", "viewer",])
                    all_projects_equal = True

                    all_selected_ids = set([new_proj["id"] for new_proj in data.data["projects_selected"]])
                    new_ids = all_selected_ids - set(projects_with_reader_access)
                    
                    if(len(new_ids) > 0):
                        email_template_name = 'cbh_core_ws/email_project_access_changed.html'
                        subject_template_name = 'cbh_core_ws/subject_project_access_changed.html'
                        all_projects_equal = False
                        data.data["message"] = "Existing user %s invited to new projects, would you like to invite anyone else?" % email
                    else:
                        if not data.data.get("remind", False):
                            raise ImmediateHttpResponse(http.HttpConflict('{"error": "User already exists, do you wish to invite again?"}'))
                        if new_user.has_usable_password():
                            email_template_name = 'cbh_core_ws/email_reminder.html'
                            subject_template_name = 'cbh_core_ws/subject_reminder.html'
                            data.data["message"] = "Sign-up reminder sent to %s, would you like to invite anyone else?" % email
                        else:
                            email_template_name = 'cbh_core_ws/email_reminder_already_logged_on.html'
                            subject_template_name = 'cbh_core_ws/subject_reminder.html'
                            data.data["message"] = "User %s reminded to look at these projects, would you like to invite anyone else?" % email
                form = self.get_form( email, new_user, data, created, request, email_template_name, subject_template_name)         

        serialized = self.serialize(request, data, desired_format)
        rc = response_class(content=serialized, content_type=build_content_type(
            desired_format), **response_kwargs)       
        return rc



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
    #                 searchfield_items.appnew_userend(item)
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
