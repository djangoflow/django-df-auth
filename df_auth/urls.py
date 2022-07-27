"""Djangoflow URL Configuration

Add these to your root URLconf:
    urlpatterns = [
        ...
        path('auth/', include('df_auth.urls'))
    ]

"""
from df_auth.viewsets import TokenViewSet
from rest_framework.routers import DefaultRouter


router = DefaultRouter()
router.register("token", TokenViewSet, basename="token")

urlpatterns = router.urls
