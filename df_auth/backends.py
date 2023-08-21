import functools
from typing import Any, List, Optional, Type

from django.contrib.auth import get_user_model
from django.contrib.auth.backends import ModelBackend
from django.http import HttpRequest
from django_otp.models import Device, SideChannelDevice
from django_otp.plugins.otp_email.models import EmailDevice
from otp_twilio.models import TwilioSMSDevice

from .exceptions import (
    DeviceDoesNotExistError,
    DeviceTakenError,
    InvalidPhoneNumberError,
    LastDeviceError,
    UserAlreadyExistError,
    WrongOTPError,
)
from .models import PhoneNumberRule
from .settings import api_settings

User = get_user_model()


def ensure_backend_effective(method: Any) -> Any:
    @functools.wraps(method)
    def wrapper(self: Any, *args: Any, **kwargs: Any) -> Any:
        if self.is_backend_effective(**kwargs):
            return method(self, *args, **kwargs)

    return wrapper


class TestEmailBackend(ModelBackend):
    def authenticate(self, request: HttpRequest, **kwargs: Any) -> Optional[User]:
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

    def get_device(self, **kwargs: Any) -> Optional[SideChannelDevice]:
        """
        Get device by identity field
        """
        identity_value = kwargs.get(self.identity_field)

        device: Optional[SideChannelDevice] = self.DeviceModel._default_manager.filter(
            **{self.device_identity_field: identity_value}
        ).first()

        if not device:
            # Create device if User identity_field is set
            user = User.objects.filter(
                **{self.identity_field: kwargs.get(self.identity_field)}
            ).first()
            if user:
                device = self.create_device(user, **kwargs)
        return device

    def get_user_devices(self, user: User) -> List[SideChannelDevice]:
        """
        Get all user devices
        """
        return self.DeviceModel._default_manager.filter(user=user)

    def send_otp(self, device: Device, **kwargs: Any) -> Optional[str]:
        """
        Sends OTP code to the User device
        """
        return device.generate_challenge()

    def create_user(self, request: HttpRequest, **kwargs: Any) -> User:
        """
        Create User instance
        """
        return User._default_manager.create(
            first_name=kwargs.get("first_name", ""),
            last_name=kwargs.get("last_name", ""),
        )

    def create_device(self, user: User, **kwargs: Any) -> SideChannelDevice:
        """
        Create Device for the User
        """
        return self.DeviceModel._default_manager.create(
            user=user, **{self.device_identity_field: kwargs.get(self.identity_field)}
        )

    def authenticate_device(self, device: SideChannelDevice, otp: str) -> User:
        if not device.verify_token(otp):
            raise WrongOTPError()

        if api_settings.OTP_IDENTITY_UPDATE_FIELD:
            self.update_user_identity_field(device)

        return device.user

    def send_invite(self, user: User, device: SideChannelDevice) -> None:
        """
        the User invites device.User to join
        """
        device.generate_challenge()

    def update_user_identity_field(self, device: SideChannelDevice) -> None:
        if api_settings.OTP_IDENTITY_UPDATE_FIELD:
            user = device.user
            setattr(
                user, self.identity_field, getattr(device, self.device_identity_field)
            )
            user.save()

    def is_backend_effective(self, **kwargs: Any) -> bool:
        """
        Returns False if we need to skip this backend
        """
        return bool(kwargs.get(self.identity_field))

    @ensure_backend_effective
    def register(self, request: HttpRequest, **kwargs: Any) -> Optional[User]:
        device = self.get_device(**kwargs)
        if device is not None:
            if api_settings.REGISTER_SEND_OTP:
                self.send_otp(device, **kwargs)
                return device.user
            else:
                raise UserAlreadyExistError()

        return self.create_user(request, **kwargs)

    @ensure_backend_effective
    def generate_challenge(self, request: HttpRequest, **kwargs: Any) -> Optional[User]:
        """
        Generate and send OTP code
        """

        device = self.get_device(**kwargs)
        user = request.user

        if device is None:
            if not user.is_authenticated:
                if api_settings.SIGNIN_AUTOCREATE_ACCOUNT:
                    user = self.create_user(request, **kwargs)
                else:
                    return None
            device = self.create_device(user, **kwargs)
        else:
            if user.is_authenticated and user != device.user:
                raise DeviceTakenError()

        self.send_otp(device, **kwargs)
        return device.user

    @ensure_backend_effective
    def set_password(self, request: HttpRequest, **kwargs: Any) -> Optional[User]:
        """
        Set password for the User
        """
        if (otp := kwargs.get("otp")) and (password := kwargs.get("password")):
            if (device := self.get_device(**kwargs)) and self.user_can_authenticate(
                device.user
            ):
                if user := self.authenticate_device(device, otp):
                    user.set_password(password)
                    user.save()
                    return user

        return None

    @ensure_backend_effective
    def authenticate(self, request: HttpRequest, **kwargs: Any) -> Optional[User]:
        """
        Check OTP and authenticate User
        """
        if otp := kwargs.get("otp"):
            if device := self.get_device(**kwargs):
                if self.user_can_authenticate(device.user):
                    return self.authenticate_device(device, otp)

        return None

    @ensure_backend_effective
    def connect(self, request: HttpRequest, **kwargs: Any) -> Optional[User]:
        """
        Check OTP and connects Device to the User
        """
        return self.authenticate(request, **kwargs)

    @ensure_backend_effective
    def unlink(self, request: HttpRequest, **kwargs: Any) -> Optional[User]:
        device = self.get_device(**kwargs)
        if not device:
            raise DeviceDoesNotExistError()

        devices = self.get_user_devices(request.user)
        if len(devices) <= 1:
            raise LastDeviceError()

        new_device = [d for d in devices if d != device][0]
        device.delete()
        self.update_user_identity_field(new_device)
        return new_device.user

    @ensure_backend_effective
    def change(self, request: HttpRequest, **kwargs: Any) -> User:
        if self.connect(request, **kwargs):
            device = self.get_device(**kwargs)
            assert device is not None

            for old_device in self.get_user_devices(request.user):
                if old_device != device:
                    old_device.delete()

            return device.user

        return None

    @ensure_backend_effective
    def invite(self, request: HttpRequest, **kwargs: Any) -> Optional[User]:
        if device := self.get_device(**kwargs):
            user = device.user
        else:
            user = self.create_user(request, **kwargs)
            device = self.create_device(user, **kwargs)

        self.send_invite(request.user, device)
        return user


class EmailOTPBackend(BaseOTPBackend):
    identity_field = "email"
    device_identity_field = "email"
    DeviceModel = EmailDevice


class TwilioSMSOTPBackend(BaseOTPBackend):
    identity_field = "phone_number"
    device_identity_field = "number"
    DeviceModel = TwilioSMSDevice

    def send_otp(self, device: TwilioSMSDevice, **kwargs: Any) -> Optional[str]:
        if not PhoneNumberRule.check_number(device.number):
            raise InvalidPhoneNumberError()

        return super().send_otp(device, **kwargs)
