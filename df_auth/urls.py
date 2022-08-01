"""Djangoflow URL Configuration

Add these to your root URLconf:
    urlpatterns = [
        ...
        path('auth/', include('df_auth.urls'))
    ]

"""
from .views.social_views import SocialLoginView, SocialConnectView
from .viewsets import TokenViewSet, OTPViewSet
from django.urls import include
from django.urls import path
from rest_framework.routers import DefaultRouter


router = DefaultRouter()
router.register("token", TokenViewSet, basename="token")
router.register("otp", OTPViewSet, basename="otp")

urlpatterns = [
    path("social/", include("social_django.urls", namespace="social")),
    path('social/signin/<str:provider>/', SocialLoginView.as_view(), name="social_login"),
    path('social/connect/<str:provider>/', SocialConnectView.as_view(), name="social_connect"),
]
urlpatterns += router.urls
