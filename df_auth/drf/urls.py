"""Djangoflow URL Configuration

Add these to your root URLconf:
    urlpatterns = [
        ...
        path('auth/', include('df_auth.urls'))
    ]

"""
from rest_framework.routers import DefaultRouter

from .viewsets import (
    OtpDeviceViewSet,
    OTPViewSet,
    SocialTokenViewSet,
    TokenViewSet,
    UserViewSet,
)

router = DefaultRouter()
router.register("token", TokenViewSet, basename="token")
router.register("users", UserViewSet, basename="users")
router.register("otp", OTPViewSet, basename="otp")
router.register("otp-devices", OtpDeviceViewSet, basename="otp-devices")

router.register("social", SocialTokenViewSet, basename="social")

urlpatterns = router.urls
