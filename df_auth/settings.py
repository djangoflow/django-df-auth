from django.conf import settings
from rest_framework.settings import APISettings


DEFAULTS = {
    "USER_IDENTITY_FIELDS": ("email",),
    "REQUIRED_AUTH_FIELDS": None,
    "OPTIONAL_AUTH_FIELDS": ("otp", "password"),
}

api_settings = APISettings(getattr(settings, "DF_AUTH", {}), DEFAULTS)
