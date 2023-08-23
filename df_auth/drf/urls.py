"""Djangoflow URL Configuration

Add these to your root URLconf:
    urlpatterns = [
        ...
        path('auth/', include('df_auth.urls'))
    ]

"""
from rest_framework.routers import DefaultRouter

from .viewsets import (
    ConnectViewSet,
    InviteViewSet,
    OtpDeviceViewSet,
    OTPViewSet,
    SetPasswordViewSet,
    SocialOAuth1TokenViewSet,
    SocialTokenViewSet,
    TokenViewSet,
    UnlinkViewSet,
    UserViewSet,
)

router = DefaultRouter()
router.register("token", TokenViewSet, basename="token")
router.register("invite", InviteViewSet, basename="invite")
router.register("connect", ConnectViewSet, basename="connect")
router.register("unlink", UnlinkViewSet, basename="unlink")
router.register("signup", UserViewSet, basename="signup")
router.register("otp", OTPViewSet, basename="otp")
router.register("otp-device", OtpDeviceViewSet, basename="otp-device")

router.register("set-password", SetPasswordViewSet, basename="set-password")
router.register("social", SocialTokenViewSet, basename="social")
router.register("social/oauth1", SocialOAuth1TokenViewSet, basename="social_oauth1")

urlpatterns = router.urls
