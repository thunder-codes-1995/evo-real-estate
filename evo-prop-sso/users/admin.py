from django.contrib import admin
from .models import User, Business, Organization
from django.contrib.auth.admin import UserAdmin


class UserAdminConfig(UserAdmin):
    model = User
    search_fields = ('mobile_no', 'email', 'full_name')  # Updated to use full_name instead of first_name & last_name
    list_filter = ('mobile_no', 'email', 'is_active', 'is_staff')
    ordering = ('-date_joined',)
    list_display = ('mobile_no', 'email', 'full_name',  # Updated to use full_name
                    'is_active', 'device_token')

    fieldsets = (
        (None, {'fields': ('email', 'mobile_no', 'full_name', 'profile_pic', 'password', 'is_active', 'is_profile_complete', 'device_token', 'business')}),
        ('Permissions',
         {'fields': ('is_staff', 'user_permissions', 'groups')}),
        ('Important dates', {'fields': ('last_login', 'date_joined', 'otp')}),
    )

    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': (
                'mobile_no', 'email', 'full_name', 'password1', 'password2', 'is_active', 'is_staff',
                'user_permissions', 'groups')}
         ),
    )

admin.site.register(User, UserAdminConfig)
admin.site.register(Business)
admin.site.register(Organization)
