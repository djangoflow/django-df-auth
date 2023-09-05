from typing import List

from django.conf import settings
from rest_framework.settings import APISettings

DEFAULTS = {
    "USER_REQUIRED_FIELDS": ("email",),
    "USER_OPTIONAL_FIELDS": (
        "first_name",
        "last_name",
        "password",
        "phone_number",
    ),
    "USER_IDENTITY_FIELDS": ("username", "email", "phone_number"),
    "REQUIRED_AUTH_FIELDS": (),
    "OPTIONAL_AUTH_FIELDS": ("otp", "password"),
    "TEST_USER_EMAIL": None,
    "OTP_IDENTITY_UPDATE_FIELD": True,
    "OTP_DEVICE_MODELS": {
        "email": "django_otp.plugins.otp_email.models.EmailDevice",
        "totp": "django_otp.plugins.otp_totp.models.TOTPDevice",
        "sms": "otp_twilio.models.TwilioSMSDevice",
    },
    "OTP_AUTO_CREATE_ACCOUNT": True,
    "SEND_OTP_UNAUTHORIZED_USER": True,
}

IMPORT_STRINGS: List[str] = []

api_settings = APISettings(getattr(settings, "DF_AUTH", IMPORT_STRINGS), DEFAULTS)
