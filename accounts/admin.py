from django.contrib import admin
# Register your models here.
# from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin

from accounts.forms import UserChangeForm, RegisterForm
from rest_framework.authtoken.admin import TokenAdmin
from accounts.models import User
# User = get_user_model()

# Remove Group Model from admin. We're not using it.
TokenAdmin.raw_id_fields = ['user']
#
class UserAdmin(BaseUserAdmin):
    # The forms to add and change user instances
    form = UserChangeForm
    add_form = RegisterForm

    # The fields to be used in displaying the User model.
    # These override the definitions on the base UserAdmin
    # that reference specific fields on auth.User.
    list_display = ('full_name' ,'email', 'is_admin')
    list_filter = ('is_admin',)
    fieldsets = (
        (None, {'fields': ('email', 'password')}),
        ('Permissions', {'fields': ('is_admin',)}),
    )
    # add_fieldsets is not a standard ModelAdmin attribute. UserAdmin
    # overrides get_fieldsets to use this attribute when creating a user.
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('email', 'password1', 'password2'),
        }),
    )
    search_fields = ('email',)
    ordering = ('email',)
    filter_horizontal = ()


# Now register the new UserAdmin...
admin.site.register(User, UserAdmin)
# ... and, since we're not using Django's built-in permissions,
# unregister the Group model from admin.
admin.site.unregister(Group)
