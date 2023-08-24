from typing import Any, Optional, Type

from django.contrib.auth import get_user_model
from django.contrib.auth.backends import ModelBackend
from django.http import HttpRequest
from django_otp.models import SideChannelDevice
from django_otp.plugins.otp_email.models import EmailDevice
from otp_twilio.models import TwilioSMSDevice

from .exceptions import (
    DeviceDoesNotExistError,
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

    def generate_challenge(self, request: HttpRequest, **kwargs: Any) -> Optional[User]:
        """
        Generate and send OTP code
        """
        if not kwargs.get(self.identity_field):
            return

        user = User.objects.filter(
            **{self.identity_field: kwargs.get(self.identity_field)}, is_active=True
        ).first()

        if not user:
            raise UserDoesNotExistError()

        device = self.DeviceModel.objects.filter(
            user=user, **{self.device_identity_field: kwargs.get(self.identity_field)}
        )

        if device is None:
            raise DeviceDoesNotExistError()

        device.generate_challenge()
        return device.user

    def authenticate(self, request: HttpRequest, **kwargs: Any) -> Optional[User]:
        """
        Check OTP and authenticate User
        """
        if not kwargs.get(self.identity_field):
            return

        user = User.objects.filter(
            **{self.identity_field: kwargs.get(self.identity_field)}, is_active=True
        ).first()

        if not user:
            raise UserDoesNotExistError()

        device = self.DeviceModel.objects.filter(
            user=user, **{self.device_identity_field: kwargs.get(self.identity_field)}
        )
        if device is None:
            raise DeviceDoesNotExistError()

        if otp := kwargs.get("otp"):
            if not device.verify_token(otp):
                raise WrongOTPError()
            return device.user

        return None


class EmailOTPBackend(BaseOTPBackend):
    identity_field = "email"
    device_identity_field = "email"
    DeviceModel = EmailDevice


class TwilioSMSOTPBackend(BaseOTPBackend):
    identity_field = "phone_number"
    device_identity_field = "number"
    DeviceModel = TwilioSMSDevice
