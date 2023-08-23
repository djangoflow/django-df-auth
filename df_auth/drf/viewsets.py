from typing import Any, List, Type

from django.conf import settings
from django.http import HttpRequest, HttpResponse
from django_otp.models import Device
from rest_framework import permissions, response, status, viewsets
from rest_framework.decorators import action
from rest_framework.settings import import_string
from rest_framework_simplejwt.settings import (
    api_settings as simple_jwt_settings,
)

from ..exceptions import DfAuthValidationError, WrongOTPError
from ..permissions import IsUnauthenticated
from ..utils import get_otp_device_models
from .serializers import (
    ConnectSerializer,
    InviteSerializer,
    OTPDeviceConfirmSerializer,
    OTPDeviceSerializer,
    OTPObtainSerializer,
    SetPasswordSerializer,
    SignupSerializer,
    SocialOAuth1TokenObtainSerializer,
    SocialTokenObtainSerializer,
    TokenObtainSerializer,
    TokenSerializer,
    UnlinkSerializer,
)


class ValidationOnlyCreateViewSet(viewsets.GenericViewSet):
    def create(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
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
    def refresh(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        return self.create(request, *args, **kwargs)

    @action(
        methods=["post"],
        detail=False,
        serializer_class=import_string(simple_jwt_settings.TOKEN_VERIFY_SERIALIZER),
    )
    def verify(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        return self.create(request, *args, **kwargs)

    @action(
        methods=["post"],
        detail=False,
        serializer_class=import_string(simple_jwt_settings.TOKEN_BLACKLIST_SERIALIZER),
    )
    def blacklist(
        self, request: HttpRequest, *args: Any, **kwargs: Any
    ) -> HttpResponse:
        if "rest_framework_simplejwt.token_blacklist" not in settings.INSTALLED_APPS:
            raise NotImplementedError

        return self.create(request, *args, **kwargs)


class UserViewSet(ValidationOnlyCreateViewSet):
    serializer_class = SignupSerializer
    permission_classes = (permissions.AllowAny,)

    # signup = create?
    # invite
    # update = change password
    # change_password = update
    # reset_password ?


class ConnectViewSet(ValidationOnlyCreateViewSet):
    serializer_class = ConnectSerializer
    permission_classes = (permissions.IsAuthenticated,)


class UnlinkViewSet(ValidationOnlyCreateViewSet):
    serializer_class = UnlinkSerializer
    permission_classes = (permissions.IsAuthenticated,)


class InviteViewSet(ValidationOnlyCreateViewSet):
    serializer_class = InviteSerializer
    permission_classes = (permissions.IsAuthenticated,)


class OTPViewSet(ValidationOnlyCreateViewSet):
    throttle_scope = "otp"
    serializer_class = OTPObtainSerializer
    permission_classes = (permissions.AllowAny,)


class SetPasswordViewSet(ValidationOnlyCreateViewSet):
    serializer_class = SetPasswordSerializer
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
    def connect(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        return self.create(request, *args, **kwargs)


class SocialOAuth1TokenViewSet(ValidationOnlyCreateViewSet):
    serializer_class = SocialOAuth1TokenObtainSerializer
    response_serializer_class = TokenSerializer
    permission_classes = (IsUnauthenticated,)

    @action(
        methods=["post"],
        detail=False,
        serializer_class=SocialOAuth1TokenObtainSerializer,
        permission_classes=(permissions.IsAuthenticated,),
    )
    def connect(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        return self.create(request, *args, **kwargs)


class OtpDeviceViewSet(
    viewsets.GenericViewSet,
    viewsets.mixins.ListModelMixin,
    viewsets.mixins.DestroyModelMixin,
    viewsets.mixins.RetrieveModelMixin,
    viewsets.mixins.CreateModelMixin,
):
    throttle_scope = "otp"
    serializer_class = OTPDeviceSerializer
    permission_classes = (permissions.IsAuthenticated,)

    def get_queryset(self) -> List[Device]:
        devices = []
        for DeviceModel in get_otp_device_models().values():
            devices.extend(DeviceModel.objects.filter(user=self.request.user))
        return devices

    def get_device_model(self) -> Type[Device]:
        device_type = self.request.GET.get("type")
        otp_device_models = get_otp_device_models()
        if device_type not in otp_device_models:
            raise DfAuthValidationError(
                f"Invalid device type. Must be one of {', '.join(otp_device_models.keys())}"
            )
        return otp_device_models[device_type]

    def get_object(self) -> Device:
        return self.get_device_model().objects.get(
            user=self.request.user, pk=self.kwargs["pk"]
        )

    @action(
        methods=["post"],
        detail=True,
        serializer_class=OTPDeviceConfirmSerializer,
    )
    def confirm(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        otp = self.request.data.get("otp")
        device: Device = self.get_object()
        if not device.verify_token(otp):
            raise WrongOTPError()

        device.confirmed = True
        device.save()

        serializer = self.get_serializer(device)
        return response.Response(serializer.data)
