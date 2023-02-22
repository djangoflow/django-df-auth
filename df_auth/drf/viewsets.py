from ..permissions import IsUnauthenticated
from .serializers import ChangeSerializer
from .serializers import ConnectSerializer
from .serializers import InviteSerializer
from .serializers import OTPObtainSerializer
from .serializers import SignupSerializer
from .serializers import SocialTokenObtainSerializer
from .serializers import TokenObtainSerializer
from .serializers import TokenSerializer
from .serializers import UnlinkSerializer
from django.conf import settings
from rest_framework import permissions
from rest_framework import response
from rest_framework import status
from rest_framework import viewsets
from rest_framework.decorators import action
from rest_framework.settings import import_string
from rest_framework_simplejwt.settings import api_settings as simple_jwt_settings


class ValidationOnlyCreateViewSet(viewsets.GenericViewSet):
    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        return response.Response(serializer.data, status=status.HTTP_200_OK)


class TokenViewSet(ValidationOnlyCreateViewSet):
    serializer_class = TokenObtainSerializer
    response_serializer_class = TokenSerializer
    permission_classes = (permissions.AllowAny,)

    @action(
        methods=["post"],
        detail=False,
        serializer_class=import_string(simple_jwt_settings.TOKEN_REFRESH_SERIALIZER),
    )
    def refresh(self, request, *args, **kwargs):
        return self.create(request, *args, **kwargs)

    @action(
        methods=["post"],
        detail=False,
        serializer_class=import_string(simple_jwt_settings.TOKEN_VERIFY_SERIALIZER),
    )
    def verify(self, request, *args, **kwargs):
        return self.create(request, *args, **kwargs)

    @action(
        methods=["post"],
        detail=False,
        serializer_class=import_string(simple_jwt_settings.TOKEN_BLACKLIST_SERIALIZER),
    )
    def blacklist(self, request, *args, **kwargs):
        if "rest_framework_simplejwt.token_blacklist" not in settings.INSTALLED_APPS:
            raise NotImplementedError

        return self.create(request, *args, **kwargs)


class SignupViewSet(ValidationOnlyCreateViewSet):
    serializer_class = SignupSerializer
    permission_classes = (permissions.AllowAny,)


class ConnectViewSet(ValidationOnlyCreateViewSet):
    serializer_class = ConnectSerializer
    permission_classes = (permissions.IsAuthenticated,)


class UnlinkViewSet(ValidationOnlyCreateViewSet):
    serializer_class = UnlinkSerializer
    permission_classes = (permissions.IsAuthenticated,)


class ChangeViewSet(ValidationOnlyCreateViewSet):
    serializer_class = ChangeSerializer
    permission_classes = (permissions.IsAuthenticated,)


class InviteViewSet(ValidationOnlyCreateViewSet):
    serializer_class = InviteSerializer
    permission_classes = (permissions.IsAuthenticated,)


class OTPViewSet(ValidationOnlyCreateViewSet):
    throttle_scope = "otp"
    serializer_class = OTPObtainSerializer
    permission_classes = (permissions.AllowAny,)


class SocialTokenViewSet(ValidationOnlyCreateViewSet):
    serializer_class = SocialTokenObtainSerializer
    response_serializer_class = TokenSerializer
    permission_classes = (IsUnauthenticated,)

    @action(
        methods=["post"],
        detail=False,
        serializer_class=SocialTokenObtainSerializer,
        permission_classes=(permissions.IsAuthenticated,),
    )
    def connect(self, request, *args, **kwargs):
        return self.create(request, *args, **kwargs)
