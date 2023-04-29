import jwt, datetime
from rest_framework.authtoken.views import ObtainAuthToken
from rest_framework.authtoken.models import Token
from rest_framework.response import Response
from rest_framework.exceptions import AuthenticationFailed
from accounts.serializers import UserSerializers, LoginSerializer, RegisterSerializer
from rest_framework import status, permissions
from djoser.views import UserViewSet
from rest_framework.authentication import TokenAuthentication
from rest_framework.generics import GenericAPIView, RetrieveUpdateAPIView
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.authtoken.views import ObtainAuthToken
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.decorators import api_view

# from rest_framework_simplejwt.tokens import AccessToken, RefreshToken

from rest_framework_simplejwt.tokens import RefreshToken
from accounts.models import User

from django.core.mail import send_mail
from django.conf import settings
import random

def send_otp(email):
	subject = "Account Verification Email From JWT App"
	otp = random.randint(1000, 9999)
	message = f"Your OTP is {otp}"
	email_from = settings.EMAIL_HOST
	send_mail(subject,message, email_from,[email])
	user_obj = User.objects.get(email=email)
	user_obj.otp = otp
	user_obj.save()

    
class Register(GenericAPIView):

	# permission_classes = (AllowAny,)
	serializer_class = RegisterSerializer

	def post(self, request, *args, **kwargs):
		serializer = self.get_serializer(data=request.data)
		data = {}
		if serializer.is_valid(raise_exception=True):
			user = serializer.save()
			send_otp(serializer.data['email'])
			data['response'] = "Registration Successful!"
			refresh = RefreshToken.for_user(user=user)
			data['refresh'] = str(refresh)
			data['access'] = str(refresh.access_token)
		# token = Token.objects.get_or_create(user=user)
		# data = serializer.data
		# print(data)
		return Response(data, status=status.HTTP_201_CREATED)

	# def post(self, request):
	# 	serializer = RegisterSerializer(data=request.data)
	# 	if serializer.is_valid():
	# 		user = serializer.save()
	# 		if user:
	# 			token = Token.objects.create(user=user)
	# 			json = serializer.data
	# 			json['token'] = token.key
	# 			print(json)
	# 			return Response(json, status=status.HTTP_201_CREATED)
	# 	return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['POST'])
def customer_login(request):
	"""
	Try to login a customer (food orderer)
	"""
	data = request.data

	try:
		email = data['email']
		password = data['password']
	except:
		return Response(status=status.HTTP_400_BAD_REQUEST)

	try:
		user = User.objects.get(username=username, password=password)
	except:
		return Response(status=status.HTTP_401_UNAUTHORIZED)

	try:
		user_token = user.auth_token.key
	except:
		user_token = Token.objects.create(user=user)

	data = {'token': user_token}
	return Response(data=data, status=status.HTTP_200_OK)


class LoginView(GenericAPIView):
	permission_classes = (AllowAny,)
	serializer_class = LoginSerializer
		
	def post(self, request, format=None):
		serializer = LoginSerializer(data=self.request.data, context={
			'request': self.request
		})
		serializer.is_valid(raise_exception=True)
		email = request.data['email']
		password = request.data['password']
		# login(request, email)
		user = User.objects.filter(email=email).first()
		if user is None:
			raise AuthenticationFailed("User not found!!!")

		if not user.check_password(password):
			raise AuthenticationFailed("Incorrect found!!!")

		payload = {
			"id": user.id,
			"full_name": user.full_name,
			"email": user.email,
			"exp": datetime.datetime.utcnow() + datetime.timedelta(days=30),
			"iat": datetime.datetime.utcnow()
		}
		token = jwt.encode(payload, "secret", algorithm="HS256")
		token = jwt.encode(payload,'secret', algorithm='HS256')
		response = Response()
		response.set_cookie(key='jwt', value=token, httponly=True)
		response.data = {
			"jwt": token
		}
		return response




# class CustomAuthToken(ObtainAuthToken):

#     def post(self, request, *args, **kwargs):
#         serializer = self.serializer_class(data=request.data,
#                                            context={'request': request})
#         serializer.is_valid(raise_exception=True)
#         user = serializer.validated_data['user']
#         token, created = Token.objects.get_or_create(user=user)
#         payload = {
#             'token': token.key,
#             'user_id': user.pk,
#             'email': user.email
#         }
#         return Response(payload)

class ActivateUser(UserViewSet):
     def get_serializer(self, *args, **kwargs):
          serializer_class = self.get_serializer_class()
          kwargs.setdefault('context', self.get_serializer_context())

          # this line is the only change from the base implementation.
          kwargs['data'] = {"uid": self.kwargs['uid'], "token": self.kwargs['token']}

          return serializer_class(*args, **kwargs)

     def activation(self, request, uid, token, *args, **kwargs):
          super().activation(request, *args, **kwargs)
          return Response(status=status.HTTP_204_NO_CONTENT)
