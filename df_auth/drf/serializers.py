from typing import Any, Dict, Optional

from django.conf import settings
from django.contrib.auth import authenticate, get_user_model
from django.contrib.auth.base_user import AbstractBaseUser
from django.contrib.auth.models import update_last_login
from django.db.models import Model
from django.utils.module_loading import import_string
from django_otp.models import Device
from django_otp.plugins.otp_email.models import EmailDevice
from django_otp.plugins.otp_totp.models import TOTPDevice
from otp_twilio.models import TwilioSMSDevice
from rest_framework import exceptions, serializers
from rest_framework_simplejwt.settings import (
    api_settings as simplejwt_settings,
)
from social_core.exceptions import AuthCanceled, AuthForbidden
from social_django.models import DjangoStorage
from social_django.utils import load_backend

from ..exceptions import Authentication2FARequiredError
from ..models import User2FA
from ..settings import api_settings
from ..strategy import DRFStrategy
from ..utils import (
    get_otp_device_choices,
    get_otp_device_models,
    get_otp_devices,
)

User = get_user_model()

AUTHENTICATION_BACKENDS = [
    import_string(backend) for backend in settings.AUTHENTICATION_BACKENDS
]


def build_fields(fields: Dict[str, str], **kwargs: Any) -> Dict[str, serializers.Field]:
    return {name: import_string(klass)(**kwargs) for name, klass in fields.items()}


def check_user_2fa(user: Optional[AbstractBaseUser], otp: Optional[str]) -> None:
    if user and hasattr(user, "user_2fa") and user.user_2fa.is_required:
        devices = [d for d in get_otp_devices(user) if d.confirmed]

        if not any(d.verify_token(otp) for d in devices):
            raise Authentication2FARequiredError(
                extra_data={"devices": OTPDeviceSerializer(devices, many=True).data}
            )


class EmptySerializer(serializers.Serializer):
    pass


class TokenSerializer(serializers.Serializer):
    token = serializers.CharField(read_only=True)
    token_class = simplejwt_settings.AUTH_TOKEN_CLASSES[0]
    user = None


class TokenCreateSerializer(TokenSerializer):
    @classmethod
    def get_token(cls, user: AbstractBaseUser) -> None:
        return cls.token_class.for_user(user)

    def validate(self, attrs: Dict[str, Any]) -> Dict[str, Any]:
        if not simplejwt_settings.USER_AUTHENTICATION_RULE(self.user):
            raise exceptions.AuthenticationFailed()

        token = self.get_token(self.user)  # type: ignore

        attrs["token"] = str(token)

        if simplejwt_settings.UPDATE_LAST_LOGIN:
            update_last_login(None, self.user)  # type: ignore

        return attrs


class TokenObtainSerializer(TokenCreateSerializer):
    def validate(self, attrs: Dict[str, Any]) -> Dict[str, Any]:
        """
        Remove empty values to pass to authenticate or send_otp
        """
        attrs = {k: v for k, v in attrs.items() if v}
        self.user = authenticate(**attrs, **self.context)  # type: ignore
        check_user_2fa(self.user, attrs.get("otp"))

        return super().validate(attrs)

    def get_fields(self) -> Dict[str, serializers.Field]:
        fields = super().get_fields()
        fields.update(
            **build_fields(
                api_settings.REQUIRED_AUTH_FIELDS,
                write_only=True,
                required=True,
                allow_blank=False,
            ),
            **build_fields(
                {
                    **api_settings.OPTIONAL_AUTH_FIELDS,
                    **api_settings.USER_IDENTITY_FIELDS,
                },
                write_only=True,
                required=False,
                allow_blank=True,
            ),
        )

        return fields


class AuthBackendSerializer(serializers.Serializer):
    backend_method_name: Optional[str] = None
    backend_extra_kwargs: Dict[str, Any] = {}

    def get_fields(self) -> Dict[str, serializers.Field]:
        return {
            **super().get_fields(),
            **build_fields(
                {
                    **api_settings.USER_IDENTITY_FIELDS,
                    **api_settings.REQUIRED_AUTH_FIELDS,
                    **api_settings.OPTIONAL_AUTH_FIELDS,
                },
                required=False,
                allow_blank=True,
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


class OTPObtainSerializer(AuthBackendSerializer):
    backend_method_name = "generate_challenge"

    def validate(self, attrs: Dict[str, Any]) -> Dict[str, Any]:
        """
        - check user auth:
          - if request.user authorized else
          - if user = authenticate(**attrs, **self.context)
          - else not authorized
        - if not authorized + OTP_SEND_UNAUTHORIZED_USER=False -> raise an error
        - send otp for the device
        """
        attrs = {k: v for k, v in attrs.items() if v}

        # check user auth
        if self.context["request"].user.is_authenticated:
            user = self.context["request"].user
        else:
            user = authenticate(**attrs, **self.context)

        # if not authorized + OTP_SEND_UNAUTHORIZED_USER=False -> raise an error
        if not user and not api_settings.OTP_SEND_UNAUTHORIZED_USER:
            raise exceptions.AuthenticationFailed(
                "Please log in to request your OTP code.",
                code="unauthorized_otp_request",
            )
        self.context["user"] = user

        # retrieve device + generate challenge
        return super().validate(attrs)


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

    def get_fields(self) -> Dict[str, serializers.Field]:
        return {
            **super().get_fields(),
            **build_fields(
                {
                    **api_settings.USER_SOCIAL_AUTH_FIELDS,
                    **api_settings.OPTIONAL_AUTH_FIELDS,
                },
                write_only=True,
                required=False,
                allow_blank=True,
            ),
        }

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

        update_fields = []
        for attr in api_settings.USER_SOCIAL_AUTH_FIELDS:
            if not getattr(self.user, attr, None):
                value = attrs.get(attr, None)
                if value:
                    setattr(self.user, attr, value)
                    update_fields.append(attr)
        if update_fields:
            self.user.save(update_fields=update_fields)

        check_user_2fa(self.user, attrs.get("otp"))
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
    extra_data = serializers.SerializerMethodField()

    def get_extra_data(self, obj: Device) -> Dict[str, str]:
        # We need `url` field for TOTP devices on `create` action
        if (
            isinstance(obj, TOTPDevice)
            and "view" in self.context
            and self.context["view"].action == "create"
        ):
            return {
                "url": obj.config_url,
            }

        return {}

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
    otp = serializers.CharField(required=True, write_only=True)

    def validate_otp(self, value: str) -> str:
        if not self.instance.verify_token(value):
            raise serializers.ValidationError("Invalid OTP code")
        return value

    def update(self, instance: Device, validated_data: Dict[str, Any]) -> Device:
        instance.confirmed = True
        instance.save()

        if api_settings.OTP_IDENTITY_UPDATE_FIELD:
            # TODO: create a common interface for this
            if isinstance(instance, EmailDevice):
                instance.user.email = instance.name
            elif isinstance(instance, TwilioSMSDevice):
                instance.user.phone_number = instance.number
            instance.user.save()

        return instance


class UserIdentitySerializer(serializers.Serializer):
    def get_fields(self) -> Dict[str, serializers.Field]:
        fields = build_fields(
            {
                **api_settings.USER_OPTIONAL_FIELDS,
                **api_settings.USER_IDENTITY_FIELDS,
            },
            required=False,
            allow_blank=True,
        )

        if "password" in fields:
            fields["password"].write_only = True

        return fields

    def validate_email(self, value: str) -> str:
        # TODO: check for black list

        # If User has no confirmed EmailDevice on update
        if (
            self.instance
            and not self.instance.emaildevice_set.filter(
                email=value, confirmed=True
            ).exists()
        ):
            raise serializers.ValidationError("You need to confirm your email first.")

        if (
            self.instance is None
            and "email" in api_settings.USER_IDENTITY_FIELDS
            and User.objects.filter(email=value).exists()
        ):
            raise serializers.ValidationError("User with this email already exists.")

        return User.objects.normalize_email(value)

    def validate_username(self, value: str) -> str:
        # TODO: check for black list
        return value

    def validate_phone_number(self, value: str) -> str:
        # TODO: check for black list
        if (
            self.instance
            and not self.instance.twiliosmsdevice_set.filter(
                number=value, confirmed=True
            ).exists()
        ):
            raise serializers.ValidationError(
                "You need to confirm your phone number first."
            )

        if (
            self.instance is None
            and "phone_number" in api_settings.USER_IDENTITY_FIELDS
            and User.objects.filter(phone_number=value).exists()
        ):
            raise serializers.ValidationError(
                "User with this phone number already exists."
            )

        return value

    def update(self, instance: User, validated_data: Dict[str, Any]) -> User:
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        instance.save()
        return instance

    def create(self, validated_data: Any) -> User:
        if not validated_data.get("username") and getattr(User, "username", False):
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


class ChangePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField(required=True, write_only=True)
    new_password = serializers.CharField(required=True, write_only=True)

    def validate_old_password(self, value: str) -> str:
        if not self.instance.check_password(value):
            raise serializers.ValidationError("Old password is incorrect.")
        return value

    def update(self, instance: User, validated_data: Dict[str, Any]) -> User:
        instance.set_password(validated_data["new_password"])
        instance.save()
        return instance


class User2FASerializer(serializers.ModelSerializer):
    class Meta:
        model = User2FA
        fields = ["is_required"]
