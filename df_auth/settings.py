from django.conf import settings
from rest_framework.settings import APISettings


DEFAULTS = {
    "USER_IDENTITY_FIELDS": ("email",),
    "REQUIRED_AUTH_FIELDS": (),
    "OPTIONAL_AUTH_FIELDS": ("otp", "password"),
    "TEST_USER_EMAIL": None,
    "EMAIL_CONFIRMED_FIELD": "email_confirmed",
    "OTP_EMAIL_UPDATE": True,
    "NOT_FOUND_ERROR_MESSAGE": "Authorization backend not found",
}

IMPORT_STRINGS = []

api_settings = APISettings(getattr(settings, "DF_AUTH", IMPORT_STRINGS), DEFAULTS)
