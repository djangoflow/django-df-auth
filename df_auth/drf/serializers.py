from typing import Any, Dict, Optional

from django.conf import settings
from django.contrib.auth import authenticate, get_user_model
from django.contrib.auth.models import AbstractUser, update_last_login
from django.db.models import Model
from django.utils.module_loading import import_string
from django_otp.models import Device
from django_otp.plugins.otp_email.models import EmailDevice
from otp_twilio.models import TwilioSMSDevice
from rest_framework import exceptions, serializers
from rest_framework_simplejwt.settings import (
    api_settings as simplejwt_settings,
)
from social_core.exceptions import AuthCanceled, AuthForbidden
from social_django.models import DjangoStorage
from social_django.utils import load_backend

from ..settings import api_settings
from ..strategy import DRFStrategy
from ..utils import get_otp_device_choices, get_otp_device_models

User = get_user_model()

AUTHENTICATION_BACKENDS = [
    import_string(backend) for backend in settings.AUTHENTICATION_BACKENDS
]


def build_required_fields(*fields: str) -> Dict[str, serializers.Field]:
    return {f: serializers.CharField(required=True, allow_blank=False) for f in fields}


def build_optional_fields(*fields: str) -> Dict[str, serializers.Field]:
    return {f: serializers.CharField(required=False, allow_blank=True) for f in fields}


class EmptySerializer(serializers.Serializer):
    pass


class IdentitySerializerMixin(serializers.Serializer):
    def get_fields(self) -> Dict[str, serializers.Field]:
        return build_optional_fields(*api_settings.USER_IDENTITY_FIELDS)

    def validate_email(self, value: str) -> str:
        return User.objects.normalize_email(value)


class TokenSerializer(serializers.Serializer):
    token = serializers.CharField(read_only=True)
    token_class = simplejwt_settings.AUTH_TOKEN_CLASSES[0]
    user = None


class TokenCreateSerializer(TokenSerializer):
    @classmethod
    def get_token(cls, user: AbstractUser) -> None:
        return cls.token_class.for_user(user)

    def validate(self, attrs: Dict[str, Any]) -> Dict[str, Any]:
        if not simplejwt_settings.USER_AUTHENTICATION_RULE(self.user):
            raise exceptions.AuthenticationFailed()

        token = self.get_token(self.user)  # type: ignore

        attrs["token"] = str(token)

        if simplejwt_settings.UPDATE_LAST_LOGIN:
            update_last_login(None, self.user)  # type: ignore

        return attrs


class TokenObtainSerializer(IdentitySerializerMixin, TokenCreateSerializer):
    def validate(self, attrs: Dict[str, Any]) -> Dict[str, Any]:
        """
        Remove empty values to pass to authenticate or send_otp
        """
        attrs = {k: v for k, v in attrs.items() if v}
        self.user = authenticate(**attrs, **self.context)  # type: ignore
        return super().validate(attrs)

    def get_fields(self) -> Dict[str, serializers.Field]:
        fields = super().get_fields()
        fields.update(
            **build_required_fields(*api_settings.REQUIRED_AUTH_FIELDS),
            **build_optional_fields(*api_settings.OPTIONAL_AUTH_FIELDS),
        )

        return fields


class AuthBackendSerializerMixin(IdentitySerializerMixin):
    backend_method_name: Optional[str] = None
    backend_extra_kwargs: Dict[str, Any] = {}

    def get_fields(self) -> Dict[str, serializers.Field]:
        return {
            **super().get_fields(),
            **build_optional_fields(
                *api_settings.REQUIRED_AUTH_FIELDS,
                *api_settings.OPTIONAL_AUTH_FIELDS,
            ),
        }

    def validate(self, attrs: Dict[str, Any]) -> Dict[str, Any]:
        attrs = {k: v for k, v in attrs.items() if v}
        attrs = super().validate(attrs)
        for backend in AUTHENTICATION_BACKENDS:
            if self.backend_method_name and hasattr(backend, self.backend_method_name):
                self.user = getattr(backend(), self.backend_method_name)(
                    **attrs, **self.backend_extra_kwargs, **self.context
                )
                if self.user:
                    return attrs
        raise exceptions.AuthenticationFailed(
            "Authorization backend not found", code="not_found"
        )


class OTPObtainSerializer(AuthBackendSerializerMixin):
    backend_method_name = "generate_challenge"


class SocialTokenObtainSerializer(TokenCreateSerializer):
    access_token = serializers.CharField(write_only=True)
    provider = serializers.ChoiceField(
        choices=[
            (backend.name, backend.name)
            for backend in AUTHENTICATION_BACKENDS
            if hasattr(backend, "name")
        ],
    )

    response = serializers.JSONField(read_only=True)

    def validate(self, attrs: Dict[str, Any]) -> Dict[str, Any]:
        request = self.context["request"]
        user = request.user if request.user.is_authenticated else None
        request.social_strategy = DRFStrategy(DjangoStorage, request)
        request.backend = load_backend(
            request.social_strategy, attrs["provider"], redirect_uri=None
        )

        try:
            self.user = request.backend.do_auth(attrs["access_token"], user=user)
        except (AuthCanceled, AuthForbidden):
            raise exceptions.AuthenticationFailed()

        return super().validate(attrs)


class OTPDeviceTypeField(serializers.ChoiceField):
    def __init__(self, **kwargs: Any) -> None:
        kwargs["source"] = "*"
        super().__init__(**kwargs)

    def to_representation(self, value: Model) -> Optional[str]:
        for type_, model in get_otp_device_models().items():
            if isinstance(value, model):
                return type_
        return None

    def to_internal_value(self, data: Any) -> Dict[str, Any]:
        return {self.field_name: data}


class OTPDeviceSerializer(serializers.Serializer):
    id = serializers.IntegerField(read_only=True)
    name = serializers.CharField(required=False)
    type = OTPDeviceTypeField(choices=get_otp_device_choices(), source="*")
    confirmed = serializers.BooleanField(read_only=True)

    def create(self, validated_data: Dict[str, Any]) -> Device:
        device_type = validated_data.pop("type")
        DeviceModel = get_otp_device_models()[device_type]

        data = {
            **validated_data,
            "user": self.context["request"].user,
            "confirmed": False,
        }

        # TODO: create common interface to
        # - check if user already this device
        # - add additional fields
        # - validate if we can create device with given name (email/phone)
        if device_type == "sms":
            data["number"] = validated_data["name"]
        if device_type == "email":
            data["email"] = validated_data["name"]

        return DeviceModel.objects.create(**data)


class OTPDeviceConfirmSerializer(serializers.Serializer):
    code = serializers.CharField(required=True, write_only=True)


class UserSerializer(serializers.Serializer):
    def get_fields(self) -> Dict[str, serializers.Field]:
        return {
            **build_required_fields(*api_settings.USER_REQUIRED_FIELDS),
            **build_optional_fields(*api_settings.USER_OPTIONAL_FIELDS),
        }

    def validate_email(self, value: str) -> str:
        # TODO: check for black list
        # Optional check if there no such EmailDevice
        return User.objects.normalize_email(value)

    def validate_username(self, value: str) -> str:
        # TODO: check for black list
        return value

    def validate_phone_number(self, value: str) -> str:
        # TODO: check for black list
        # Optional check if there no such TwilioSMSDevice
        return value

    def create(self, validated_data: Any) -> User:
        if not validated_data.get("username"):
            validated_data["username"] = (
                validated_data["email"] or validated_data["phone_number"]
            )

        user = User(**validated_data)
        if validated_data.get("password"):
            user.set_password(validated_data["password"])
        user.save()

        # TODO: create common interface
        if user.email:  # type: ignore
            EmailDevice.objects.create(
                user=user, email=user.email, confirmed=False, name=user.email  # type: ignore
            )

        if user.phone_number:  # type: ignore
            TwilioSMSDevice.objects.create(
                user=user,
                number=user.phone_number,
                confirmed=False,
                name=user.phone_number,
            )

        return user
