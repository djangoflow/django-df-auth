"""Djangoflow URL Configuration

Add these to your root URLconf:
    urlpatterns = [
        ...
        path('auth/', include('df_auth.urls'))
    ]

"""
from django.urls import path
from rest_framework.routers import DefaultRouter

from .viewsets import TokenViewSet

router = DefaultRouter()
router.register("token", TokenViewSet)

urlpatterns = [path("", router.urls)]
