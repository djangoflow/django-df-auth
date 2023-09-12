from df_api_drf.exceptions import ExtraDataAPIException
from django.utils.translation import gettext_lazy as _
from rest_framework import status
from rest_framework.exceptions import (
    PermissionDenied,
    ValidationError,
)


class DfAuthValidationError(ValidationError):
    """
    This is a base exception for custom validation errors
    """

    status_code = status.HTTP_400_BAD_REQUEST
    default_detail = _("Authentication error")


class WrongOTPError(DfAuthValidationError):
    """
    This exception is used when token for otp is not verified
    """

    default_detail = _("Wrong or expired one-time password")
    default_code = "wrong_otp"


class UserAlreadyExistError(DfAuthValidationError):
    """
    This exception is used when user already exists
    """

    default_detail = _("User with this identity already exists, try logging in")
    default_code = "user_already_exists"


class UserDoesNotExistError(DfAuthValidationError):
    """
    This exception is used when user already exists
    """

    default_detail = _("User with this identity does not exist, try signup instead")
    default_code = "user_does_not_exist"


class DeviceTakenError(DfAuthValidationError):
    """
    This exception is used when device is already registered
    """

    default_detail = _("This device is already taken, unlink it first")
    default_code = "device_already_taken"


class InvalidPhoneNumberError(DfAuthValidationError):
    """
    This exception is used when phone number is not valid
    """

    default_detail = _("Invalid phone number")
    default_code = "invalid_phone_number"


class DeviceDoesNotExistError(DfAuthValidationError):
    """
    This exception is used when device is not registered
    """

    default_detail = _("Device does not exist")
    default_code = "device_does_not_exists"


class LastDeviceError(DfAuthValidationError):
    """
    This exception is used when there is no device registered with user
    """

    default_detail = _("Cannot remove the last device")
    default_code = "last_device_error"


class Authentication2FARequiredError(ExtraDataAPIException):
    default_detail = "2FA is required for this user."
    default_code = "2fa_required"
    status_code = status.HTTP_401_UNAUTHORIZED


class SignupNotAllowedError(PermissionDenied):
    default_detail = "Signup is disabled."
    default_code = "signup_not_allowed"
