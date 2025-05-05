import requests
from django.contrib import admin
from crud_admin import settings
from .models import *
from django.contrib.auth.models import User
# from django.contrib.sites.models import Site
from django.contrib.auth.models import Group
from django.contrib.auth.models import Group

from import_export.admin import ImportExportModelAdmin

# admin.site.unregister(User)
# admin.site.unregister(Group)
# admin.site.unregister(Site)

class CollectionFieldsInline(admin.TabularInline):
    model = CollectionFields
    min_num = 1
    extra = 0
    can_delete = False

class CollectionAdmin(ImportExportModelAdmin):
    list_display = ['name']
    inlines = [CollectionFieldsInline]
    search_fields = ['name']

    def save_model(self, request, obj, form, change):
        super().save_model(request, obj, form, change)
        self.call_api(obj)

    def get_auth_token(self):
        url = f"{settings.CD_SSO_SERVER_URL}/api/auth/login/"
        payload = {"email":settings.SSO_ADMIN_USER_EMAIL, "password":settings.SSO_ADMIN_USER_PASSWORD}
        sso_response = requests.post(url,json=payload)
        try:
            sso_response.raise_for_status()
        except requests.exceptions.HTTPError as err:
            print(err)
            return False

        sso_response_json = sso_response.json()
        if sso_response_json['message'] == 'success':
            response_data = sso_response_json.get('result', {})
            access_token = response_data.get('token',{}).get('access')
            return access_token
        else:
            return False

    def call_api(self,obj):
        url = f"{settings.CD_CRUD_SERVER_URL}/api/collection/"

        type_list = []
        fname_list = []
        seeder_list = []
        required_list = []
        sequence_list = []
        unique_list = []
        display_list = []
        field_display_name_list = []
        field_desc_list = []

        collection_fields = CollectionFields.objects.filter(collection=obj)
        for field in collection_fields:
            type_list.append(field.type)
            fname_list.append(field.name)
            seeder_list.append(field.seeder.id if field.seeder else None)
            required_list.append(field.required)
            sequence_list.append(float(field.sequence))
            unique_list.append(field.unique)
            display_list.append(field.display)
            field_display_name_list.append(field.display_name)
            field_desc_list.append(field.field_desc)

        data = {
            'business_code': obj.business_code,
            'name': obj.name,
            'display_name': obj.display_name,
            'group': obj.group,
            'is_seeder': obj.is_seeder,
            'have_library': obj.have_library,
            'fname': fname_list,
            'field_display_name': fname_list,
            'type': type_list,
            'seeder': seeder_list,
            'required': required_list,
            'display': display_list,
            'unique': unique_list,
            'sequence': sequence_list,
            'field_desc': field_desc_list
        }

        form_data = []
        for key, values in data.items():
            if not isinstance(values, list):
                form_data.append((key, values))
            else:
                for value in values:
                    form_data.append((key, value))

        try:
            token = self.get_auth_token()
            if token:
                response = requests.post(url, data=form_data,headers={'Authorization': f"Bearer {token}"})
                response.raise_for_status()
                print(f'Successfully called the API: {response.json()}')
            else:
                print('Authorization failed')
        except requests.RequestException as e:
            print(f'Failed to call the API: {e}')


admin.site.register(Collection, CollectionAdmin)


class SeederAdmin(ImportExportModelAdmin):
    list_display = [f.name for f in Seeder._meta.fields]

admin.site.register(Seeder, SeederAdmin)

class OrganizationAdmin(ImportExportModelAdmin):
    list_display = [f.name for f in Organization._meta.fields]

admin.site.register(Organization, OrganizationAdmin)

class BizAppAdmin(ImportExportModelAdmin):
    list_display = [f.name for f in BizApp._meta.fields]

admin.site.register(BizApp, BizAppAdmin)


class BusinessAdmin(ImportExportModelAdmin):
    list_display = [f.name for f in Business._meta.fields]

admin.site.register(Business, BusinessAdmin)

class AnalyticsAdmin(ImportExportModelAdmin):
    list_display = [f.name for f in Analytics._meta.fields]

admin.site.register(Analytics, AnalyticsAdmin)

class CollectionFieldsAdmin(ImportExportModelAdmin):
    list_display = [f.name for f in CollectionFields._meta.fields]

admin.site.register(CollectionFields, CollectionFieldsAdmin)

# admin.site.disable_action('delete_selected')
