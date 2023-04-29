from django import forms
from django.contrib.auth import get_user_model
from django.contrib import admin
from django.contrib.auth.models import Group
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.contrib.auth.forms import ReadOnlyPasswordHashField
from django.core.exceptions import ValidationError

from accounts.models import User

# User = get_user_model()

class RegisterForm(forms.ModelForm):
    password1 = forms.CharField(label='Password', widget=forms.PasswordInput)
    password2 = forms.CharField(label='Password confirmation', widget=forms.PasswordInput)

    class Meta:
        model = User
        fields = ('email', 'full_name',)

    def clean_password2(self):
        password1 = self.cleaned_data.get("password1")
        password2 = self.cleaned_data.get("password2")
        if password1 and password2 and password1 != password2:
            raise ValidationError("Passwords don't match")
        return password2

    def clean_email(self):
        email = self.cleaned_data.get('email')
        qs = User.objects.filter(email=email)
        if qs.exists():
            raise forms.ValidationError("email is taken")
        return email


    def save(self, commit=True):
        user = super().save(commit=False)
        user.set_password(self.cleaned_data["password1"])
        if commit:
            user.save()
        return user


# class UserAdminCreationForm(forms.ModelForm):
#     password = forms.CharField(widget=forms.PasswordInput)
#     password_2 = forms.CharField(label='Confirm Password', widget=forms.PasswordInput)
#
#     class Meta:
#         model = User
#         fields = ['email']
#
#     def clean(self):
#         cleaned_data = super().clean()
#         password = cleaned_data.get("password")
#         password_2 = cleaned_data.get("password_2")
#         if password is not None and password != password_2:
#             self.add_error("password_2", "Your passwords must match")
#         return cleaned_data
#
#     def save(self, commit=True):
#         # Save the provided password in hashed format
#         user = super().save(commit=False)
#         user.set_password(self.cleaned_data["password"])
#         if commit:
#             user.save()
#         return user
#

class UserChangeForm(forms.ModelForm):
    password = ReadOnlyPasswordHashField()

    class Meta:
        model = User
        fields = ('full_name', 'email', 'password',  'is_active', 'is_admin')
