"""Djangoflow URL Configuration

Add these to your root URLconf:
    urlpatterns = [
        ...
        path('auth/', include('df_auth.urls'))
    ]

"""
from django.urls import path
from .views import DemoAPIView
from .viewsets import TokenViewSet
from rest_framework.routers import DefaultRouter

router = DefaultRouter()
router.register('token', TokenViewSet)

urlpatterns = [
    path('demo/', DemoAPIView.as_view()),
    path('', router.urls)
]
