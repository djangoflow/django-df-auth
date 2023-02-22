from django.utils.translation import gettext_lazy as _
from rest_framework.exceptions import ValidationError


class DfAuthError(ValidationError):
    default_detail = _("Authentication error")


class WrongOTPError(DfAuthError):
    default_detail = _("Wrong or expired one-time password")


class UserAlreadyExistError(DfAuthError):
    default_detail = _("User already exist")


class DeviceTakenError(DfAuthError):
    default_detail = _("This device is already taken")


class DeviceDoesNotExistError(DfAuthError):
    default_detail = _("Device does not exist")


class LastDeviceError(DfAuthError):
    default_detail = _("Cannot remove the last device")
