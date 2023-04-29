import djoser.conf
from rest_framework import serializers
from django.contrib.auth import get_user_model, authenticate
from rest_framework.validators import UniqueValidator
from django.db.models import Q # for queries
from uuid import uuid4
from rest_framework import exceptions, serializers
# from accounts.models import User
from django.contrib.auth import authenticate
from django.contrib.auth.models import update_last_login
from django.core.exceptions import ValidationError
from rest_framework.settings import api_settings
from rest_framework.views import Response
from django.contrib.auth.models import update_last_login
from django.contrib.auth import authenticate
from djoser.conf import settings
from django.contrib.auth.models import update_last_login
from rest_framework_simplejwt.serializers import TokenObtainSerializer
from rest_framework_simplejwt.settings import api_settings
from rest_framework_simplejwt.tokens import RefreshToken
from djoser import utils
from djoser.compat import get_user_email, get_user_email_field_name
from djoser.conf import settings
from djoser.serializers import TokenSerializer

User = get_user_model()

class UserSerializers(serializers.ModelSerializer):

	class Meta:
		model = User
		fields = '__all__'

class RegisterSerializer(serializers.ModelSerializer):
	password = serializers.CharField(style={'input_type': 'password'}, write_only=True)
	password2 = serializers.CharField(style={'input_type': 'password'}, write_only=True)

	class Meta:
		model = User
		fields = ('full_name', 'email', 'password', 'password2')
		extra_kwargs = {
			'password': {'write_only': True}
		}

	def save(self):
		password = self.validated_data['password']
		password2 = self.validated_data['password2']

		if password != password2:
			raise serializers.ValidationError(
				{'error': 'passwords did not match'})

		user = User(email=self.validated_data['email'],
					full_name=self.validated_data['full_name'],is_active=True)
		user.set_password(self.validated_data['password'])
		user.save()
		return user


class LoginSerializer(serializers.Serializer):

	email = serializers.CharField()
	password = serializers.CharField(write_only=True)

	def validate(self, data):
		user = authenticate(**data)
		if user and user.is_active:
			return user
		raise serializers.ValidationError("Incorrect Credentials")

	


class CustomTokenCreateSerializer(TokenObtainSerializer):
	password = serializers.CharField(required=False, style={"input_type": "password"})
	
	# default_error_messages = {
	# 	"invalid_credentials": settings.CONSTANTS.messages.INVALID_CREDENTIALS_ERROR,
	# 	"inactive_account": settings.CONSTANTS.messages.INACTIVE_ACCOUNT_ERROR,
	# }
	
	@classmethod
	def get_token(cls, user):
		return RefreshToken.for_user(user)
		
	def __init__(self, *args, **kwargs):
		super().__init__(*args, **kwargs)
		self.user = None
		self.fields[settings.LOGIN_FIELD] = serializers.CharField(required=False)
	
	def validate(self, attrs):
		password = attrs.get("password")
		params = {djoser.conf.settings.LOGIN_FIELD: attrs.get(djoser.conf.settings.LOGIN_FIELD)}
		self.user = authenticate(
			request=self.context.get("request"), **params, password=password
		)
		

		if not self.user:
			self.user = User.objects.filter(**params).first()
			if self.user and not self.user.check_password(password):
				self.fail("invalid_credentials")
		if self.user and self.user.is_active:
			data = super().validate(attrs)
			refresh = self.get_token(self.user)
	
			data['refresh'] = str(refresh)
			data['access'] = str(refresh.access_token)
	
			if api_settings.UPDATE_LAST_LOGIN:
				update_last_login(None, self.user)
			
		print(data)
		return data
		# return data

		# if self.user and not self.user.is_active:
		# 	self.fail("inactive_account")
		# self.fail("invalid_credentials")