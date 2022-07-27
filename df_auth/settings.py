from django.conf import settings
from rest_framework.settings import APISettings


DEFAULTS = {
    "USER_IDENTITY_FIELDS": ("email",),
    "PASSWORD_REQUIRED": False,
    "OTP_REQUIRED": False,
}

api_settings = APISettings(getattr(settings, "DF_AUTH", {}), DEFAULTS)
