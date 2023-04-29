from django.urls import path, include
from rest_framework.authtoken import views
from djoser.views import TokenDestroyView
from accounts import views


urlpatterns = [
    path('register/', views.Register.as_view()),
    path('login/', views.LoginView.as_view()),
    path('aut-login/', views.customer_login),
    # path('api-token-auth/', views.CustomAuthToken.as_view()),
    # path('token/destroy/', TokenDestroyView.as_view()),
    path('auth/', include('djoser.urls')),
    path('auth/', include('djoser.urls.authtoken')),
    path('auth/users/activation/{uid}/{token}', views.ActivateUser.as_view({'get': 'activation'}), name='activation'),
]
