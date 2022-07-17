"""Djangoflow URL Configuration

Add these to your root URLconf:
    urlpatterns = [
        ...
        path('auth/', include('df_auth.urls'))
    ]

"""
from django.urls import path
from .views import DemoAPIView

urlpatterns = [
    path('demo/', DemoAPIView.as_view()),
]
