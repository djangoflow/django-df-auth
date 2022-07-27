"""Djangoflow URL Configuration

Add these to your root URLconf:
    urlpatterns = [
        ...
        path('auth/', include('df_auth.urls'))
    ]

"""
from rest_framework.routers import DefaultRouter

from df_auth.viewsets import TokenViewSet

router = DefaultRouter()
router.register("token", TokenViewSet, basename="token")

urlpatterns = router.urls
