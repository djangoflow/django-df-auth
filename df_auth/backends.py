from typing import Any, Optional, Type

from django.contrib.auth import get_user_model
from django.contrib.auth.backends import ModelBackend
from django.http import HttpRequest
from django_otp.models import SideChannelDevice
from django_otp.plugins.otp_email.models import EmailDevice
from otp_twilio.models import TwilioSMSDevice

from .exceptions import (
    UserDoesNotExistError,
    WrongOTPError,
)
from .settings import api_settings

User = get_user_model()


class TestEmailBackend(ModelBackend):
    def authenticate(self, request: Optional[HttpRequest], **kwargs: Any) -> Optional[User]:  # type: ignore
        if (
            api_settings.TEST_USER_EMAIL
            and kwargs.get("email") == api_settings.TEST_USER_EMAIL
        ):
            return User._default_manager.get(email=api_settings.TEST_USER_EMAIL)

        return None


class BaseOTPBackend(ModelBackend):
    identity_field: str
    device_identity_field: str
    DeviceModel: Type[SideChannelDevice]

    def update_user_identity_field(self, device: SideChannelDevice) -> None:
        if api_settings.OTP_IDENTITY_UPDATE_FIELD:
            user = device.user
            setattr(
                user, self.identity_field, getattr(device, self.device_identity_field)
            )
            user.save()

    def generate_challenge(
        self, request: HttpRequest, user: Optional[User], **kwargs: Any
    ) -> Optional[User]:
        """
        - if user not authorized:
            - find User by some identity field: email/phone.
                - if not found:
                    - if OTP_AUTO_CREATE_ACCOUNT -> create a User with form data
                    - else: raise an error "No user, please register"

        - Create active device if does not exist
        - send otp for the device
        """
        if not kwargs.get(self.identity_field):
            return None

        if not user:
            user = User.objects.filter(
                **{self.identity_field: kwargs.get(self.identity_field)}, is_active=True
            ).first()
            if not user:
                if api_settings.OTP_AUTO_CREATE_ACCOUNT and api_settings.SIGNUP_ALLOWED:
                    user = User.objects.create(
                        **{
                            k: v
                            for k, v in kwargs.items()
                            if k
                            in [
                                *api_settings.USER_OPTIONAL_FIELDS,
                                *api_settings.USER_IDENTITY_FIELDS,
                            ]
                        }
                    )
                else:
                    raise UserDoesNotExistError()

        device, _ = self.DeviceModel.objects.get_or_create(
            user=user,
            **{self.device_identity_field: kwargs.get(self.identity_field)},
            defaults={
                "name": kwargs.get("name", kwargs.get(self.identity_field)),
                "confirmed": True,  # Because User already has this device as identity field
            },
        )

        self.send_challenge(device, request, **kwargs)
        return device.user

    def send_challenge(
        self, device: SideChannelDevice, request: HttpRequest, **kwargs: Any
    ) -> None:
        device.generate_challenge()

    def authenticate(self, request: Optional[HttpRequest], **kwargs: Any) -> Optional[User]:  # type: ignore
        """
        Check OTP and authenticate User
        """
        if not kwargs.get(self.identity_field) or not kwargs.get("otp"):
            return None

        user = User.objects.filter(
            **{self.identity_field: kwargs.get(self.identity_field)}, is_active=True
        ).first()

        if not user:
            return None

        device = self.DeviceModel.objects.filter(
            user=user, **{self.device_identity_field: kwargs.get(self.identity_field)}
        ).first()
        if device is None:
            return None

        if not device.verify_token(kwargs.get("otp")):
            raise WrongOTPError()

        return device.user


class EmailOTPBackend(BaseOTPBackend):
    identity_field = "email"
    device_identity_field = "email"
    DeviceModel = EmailDevice


class TwilioSMSOTPBackend(BaseOTPBackend):
    identity_field = "phone_number"
    device_identity_field = "number"
    DeviceModel = TwilioSMSDevice
