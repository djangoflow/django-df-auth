from django.conf import settings
from rest_framework.settings import APISettings


DEFAULTS = {
    "USER_IDENTITY_FIELDS": ("email", "phone_number"),
    "REQUIRED_AUTH_FIELDS": (),
    "OPTIONAL_AUTH_FIELDS": ("otp", "password"),
    "TEST_USER_EMAIL": None,
    "OTP_IDENTITY_UPDATE_FIELD": True,
    "REGISTER_SEND_OTP": False,
    "SIGNIN_AUTOCREATE_ACCOUNT": True,
}

IMPORT_STRINGS = []

api_settings = APISettings(getattr(settings, "DF_AUTH", IMPORT_STRINGS), DEFAULTS)
