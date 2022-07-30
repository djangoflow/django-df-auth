"""Djangoflow URL Configuration

Add these to your root URLconf:
    urlpatterns = [
        ...
        path('auth/', include('df_auth.urls'))
    ]

"""
from .viewsets import OTPViewSet
from .viewsets import TokenViewSet
from .viewsets import SignIn, Connect, CallBack
from django.contrib import admin
from django.urls import include
from django.urls import path
from rest_framework.routers import DefaultRouter


router = DefaultRouter()
router.register("token", TokenViewSet, basename="token")
router.register("otp", OTPViewSet, basename="otp")

urlpatterns = [
    path('admin/', admin.site.urls),
    path("social/", include("social_django.urls", namespace="social")),
    path("social/signin/<str:provider>/", SignIn.as_view(), name='sign-in'),
    path("social/connect/<str:provider>/", Connect.as_view(), name='connect'),
    path('social/callback/', CallBack.as_view(), name='call-back'),
]
urlpatterns += router.urls
