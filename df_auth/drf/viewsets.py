from typing import Any, Iterable, List, Type

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.exceptions import FieldDoesNotExist
from django.http import HttpRequest, HttpResponse
from django_otp.models import Device
from drf_spectacular.types import OpenApiTypes
from drf_spectacular.utils import OpenApiParameter, extend_schema
from rest_framework import permissions, response, status, viewsets
from rest_framework.decorators import action
from rest_framework.permissions import BasePermission
from rest_framework.settings import import_string
from rest_framework_simplejwt.settings import (
    api_settings as simple_jwt_settings,
)

from ..exceptions import (
    DfAuthValidationError,
)
from ..models import User2FA
from ..permissions import IsUnauthenticated, IsUserCreateAllowed
from ..utils import get_otp_device_models, get_otp_devices
from .serializers import (
    ChangePasswordSerializer,
    OTPDeviceConfirmSerializer,
    OTPDeviceSerializer,
    OTPObtainSerializer,
    SocialTokenObtainSerializer,
    TokenObtainSerializer,
    TokenSerializer,
    User2FASerializer,
    UserIdentitySerializer,
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
    def connect(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        return self.create(request, *args, **kwargs)


otp_device_detail_params = [
    OpenApiParameter(
        name="type",
        type=OpenApiTypes.STR,
        location=OpenApiParameter.QUERY,
        description="OTP Device type",
        required=True,
    )
]


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
        return get_otp_devices(self.request.user)

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

    @extend_schema(parameters=otp_device_detail_params)
    @action(
        methods=["post"],
        detail=True,
        serializer_class=OTPDeviceConfirmSerializer,
    )
    def confirm(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        serializer = OTPDeviceConfirmSerializer(
            data=request.data, instance=self.get_object()
        )
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return response.Response({})

    @extend_schema(parameters=otp_device_detail_params)
    def destroy(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        return super().destroy(request, *args, **kwargs)

    @extend_schema(parameters=otp_device_detail_params)
    def retrieve(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        return super().retrieve(request, *args, **kwargs)


class UserViewSet(
    viewsets.GenericViewSet,
    viewsets.mixins.RetrieveModelMixin,
    viewsets.mixins.CreateModelMixin,
    viewsets.mixins.UpdateModelMixin,
):
    serializer_class = UserIdentitySerializer
    permission_classes = (permissions.IsAuthenticated,)
    http_method_names = ["get", "post", "patch"]

    def get_permissions(self) -> Iterable[BasePermission]:
        if self.action == "create":
            return (IsUserCreateAllowed(),)
        return super().get_permissions()

    def get_object(self) -> Any:
        return self.request.user

    def perform_create(self, serializer: UserIdentitySerializer) -> None:
        User = get_user_model()
        try:
            User._meta.get_field("created_by")
            kwargs = {
                "created_by": self.request.user
                if self.request.user.is_authenticated
                else None
            }
        except FieldDoesNotExist:
            kwargs = {}
        serializer.save(**kwargs)

    @action(
        detail=True,
        methods=["POST"],
        serializer_class=ChangePasswordSerializer,
        url_path="set-password",
    )
    def set_password(
        self, request: HttpRequest, *args: Any, **kwargs: Any
    ) -> HttpResponse:
        return super().update(request, *args, **kwargs)

    @action(
        detail=True,
        methods=["GET", "PATCH"],
        serializer_class=User2FASerializer,
        url_path="two-fa",
    )
    def two_fa(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        instance = User2FA.objects.get_or_create(user=self.get_object())[0]
        if request.method == "GET":
            serializer = self.get_serializer(instance)
        else:
            serializer = self.get_serializer(instance, data=request.data, partial=True)
            serializer.is_valid(raise_exception=True)
            serializer.save()
        return response.Response(serializer.data)
