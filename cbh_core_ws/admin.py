# -*- coding: utf-8 -*-

from django.contrib import admin
from cbh_core_model.models import Project, PinnedCustomField, CustomFieldConfig, SkinningConfig, ProjectType, DataFormConfig

from django.contrib.admin import ModelAdmin


from django.forms.widgets import HiddenInput, TextInput
from django.db import models
import json
from solo.admin import SingletonModelAdmin



from django import forms







class GrappelliSortableHiddenMixin(object):
    """
    Mixin which hides the sortable field with Stacked and Tabular inlines.
    This mixin must precede admin.TabularInline or admin.StackedInline.
    """
    sortable_field_name = "position"

    def formfield_for_dbfield(self, db_field, **kwargs):
        if db_field.name == self.sortable_field_name:
            kwargs["widget"] = HiddenInput()
        return super(GrappelliSortableHiddenMixin, self).formfield_for_dbfield(db_field, **kwargs)



class DataFormConfigAdmin(ModelAdmin):
    exclude= ["created_by", "parent"]
    # def get_queryset(self, request):
    #     qs = super(DataFormConfigAdmin, self).get_queryset(request)
    #     return qs.filter(human_added=True)


    def save_model(self, request, obj, form, change): 
        obj.created_by= request.user
        obj.save()
        

        obj.get_all_ancestor_objects(request)




class PinnedCustomFieldAdmin(ModelAdmin):
    list_display = ["name", 
                    "description" ,
                    "field_type",
                    "allowed_values","pinned_for_datatype", "field_key"]

    
    exclude = ["field_key", "standardised_alias", "custom_field_config","part_of_blinded_key", "position"]

    def get_queryset(self, request):
        qs = super(PinnedCustomFieldAdmin, self).get_queryset(request)
        return qs.filter(custom_field_config=None)

    def save_model(self, request, obj, form, change): 
        obj.position = 0
        obj.save()


class PinnedCustomFieldInlineForm(forms.ModelForm):
    standardised_alias = forms.ModelChoiceField(required=False, queryset=PinnedCustomField.objects.exclude(pinned_for_datatype=None).order_by("field_key"), empty_label="Not Mapped")

    class Meta:
        model = PinnedCustomField
        exclude=["field_key", "pinned_for_datatype", "attachment_field_mapped_to"]




class PinnedCustomFieldInline( GrappelliSortableHiddenMixin, admin.TabularInline, ): #GrappelliSortableHiddenMixin
    model = PinnedCustomField
    exclude = ["field_key", "pinned_for_datatype",  "attachment_field_mapped_to"]
  
    sortable_field_name = "position"
    formfield_overrides = {
        models.CharField: {'widget': TextInput(attrs={'size':'20'})},
    }
    extra = 3
    form = PinnedCustomFieldInlineForm

    

    def get_extra (self, request, obj=None, **kwargs):
        """Dynamically sets the number of extra forms. 0 if the related object
        already exists or the extra configuration otherwise."""
        if obj:
            # Don't add any extra forms if the related object already exists.
            return 0
        return self.extra
#Make a template have to be chosen in order to create a schema and make it impossible to edit schemas once created then versioning not needed



class CustomFieldConfigAdmin(ModelAdmin):
    
    exclude= ["created_by", ]

    search_fields = ('name',)
    ordering = ('-created',)
    date_hierarchy = 'created' 
    inlines = [PinnedCustomFieldInline,]

    
    def get_readonly_fields(self, request, obj=None):
        if obj: # editing an existing object
            return self.readonly_fields + ('schemaform',)
        return self.readonly_fields

    def save_model(self, request, obj, form, change): 
        obj.created_by= request.user
        obj.save()
    #     if obj.pinned_custom_field.all().count() == 0 and obj.schemaform:
    #         data = json.loads(form.cleaned_data["schemaform"])["form"]
    #         for position, field in enumerate(data):
    #             PinnedCustomField.objects.create(allowed_values=field["allowed_values"],
    #                                             custom_field_config=obj,
    #                                             field_type=field["field_type"],
    #                                             position=field["position"],
    #                                             name=field["key"],
    #                                             description=field["placeholder"])
        
                                                
                


    # def log_change(self, request, object, message):
    #     """
    #     Log that an object has been successfully changed.
    #     The default implementation creates an admin LogEntry object.
    #     """
    #     super(CustomFieldConfigAdmin, self).log_change(request, object, message)
    #     cfr = ChemregProjectResource()
    #     if object.__class__.__name__ == "CustomFieldConfig":
    #         schemaform = json.dumps(cfr.get_schema_form(object,"" ))
    #         object.schemaform = schemaform
    #         object.save()


    formfield_overrides = {
        models.CharField: {'widget': TextInput(attrs={'size':'20'})},
    }

class ProjectTypeAdmin(ModelAdmin):
    list_display = ('name', 'show_compounds')





class ProjectAdmin(ModelAdmin):
    prepopulated_fields = {"project_key": ("name",)}
    list_display = ('name', 'project_key', 'created', 'project_type')
    search_fields = ('name',)
    ordering = ('-created',)
    date_hierarchy = 'created'
    exclude= ["created_by"]

    def save_model(self, request, obj, form, change): 
        obj.created_by = request.user
        obj.save()

        # if project.project_type.name == "Assay":
        #     cfc_ids = [dfc.l0_id for dfc in project.enabled_forms.all()]
        #     cfc_ids = list(set(cfc_ids))
        #     if len(cfc_ids) == 1:
        #         #We have a single l0 datapoint therefore configure the first data point classification
        #         root_dfc = DataFormConfig.objects.get(l0_id=cfc_ids[0])
        #         DataPointClassification.objects.get(l0_id=cfc_ids[0], l1_id=None, l2_id=None, l3_id=None, l4_id=None)







admin.site.register(CustomFieldConfig, CustomFieldConfigAdmin)
admin.site.register(Project, ProjectAdmin)
admin.site.register(ProjectType, ProjectTypeAdmin)
admin.site.register(SkinningConfig, SingletonModelAdmin)
admin.site.register(DataFormConfig, DataFormConfigAdmin)
admin.site.register(PinnedCustomField, PinnedCustomFieldAdmin)