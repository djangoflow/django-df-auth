"""Djangoflow URL Configuration

Add these to your root URLconf:
    urlpatterns = [
        ...
        path('auth/', include('df_auth.urls'))
    ]

"""
from .viewsets import ChangeViewSet
from .viewsets import ConnectViewSet
from .viewsets import InviteViewSet
from .viewsets import OTPViewSet
from .viewsets import SignupViewSet
from .viewsets import SocialTokenViewSet
from .viewsets import TokenViewSet
from .viewsets import UnlinkViewSet
from rest_framework.routers import DefaultRouter


router = DefaultRouter()
router.register("token", TokenViewSet, basename="token")
router.register("invite", InviteViewSet, basename="invite")
router.register("connect", ConnectViewSet, basename="connect")
router.register("unlink", UnlinkViewSet, basename="unlink")
router.register("change", ChangeViewSet, basename="change")
router.register("signup", SignupViewSet, basename="signup")
router.register("otp", OTPViewSet, basename="otp")
router.register("social", SocialTokenViewSet, basename="social")

urlpatterns = router.urls
