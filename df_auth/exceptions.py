from django.utils.translation import gettext_lazy as _
from rest_framework.exceptions import ValidationError


class DfAuthError(ValidationError):
    # TODO add codes
    default_detail = _("Authentication error")


class WrongOTPError(DfAuthError):
    default_detail = _("Wrong or expired one-time password")


class UserAlreadyExistError(DfAuthError):
    # code = "signup_user_exists"
    default_detail = _("User with this identity already exists, try logging in")


class DeviceTakenError(DfAuthError):
    default_detail = _("This device is already taken, unlink it first")


class InvalidPhoneNumberError(DfAuthError):
    default_detail = _("Invalid phone number")


class OTPDeviceDoesNotExistError(DfAuthError):
    default_detail = _("Device does not exist")


class LastDeviceError(DfAuthError):
    default_detail = _("Cannot remove the last device")
