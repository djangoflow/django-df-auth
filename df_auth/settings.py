from typing import List

from django.conf import settings
from rest_framework.settings import APISettings

DEFAULTS = {
    "USER_IDENTITY_FIELDS": ("email", "phone_number"),
    "REQUIRED_AUTH_FIELDS": (),
    "OPTIONAL_AUTH_FIELDS": ("otp", "password"),
    "TEST_USER_EMAIL": None,
    "OTP_IDENTITY_UPDATE_FIELD": True,
    "OTP_DEVICE_MODELS": {
        "email": "django_otp.plugins.otp_email.models.EmailDevice",
        "totp": "django_otp.plugins.otp_totp.models.TOTPDevice",
        "sms": "otp_twilio.models.TwilioSMSDevice",
    },
    "REGISTER_SEND_OTP": False,
    # Must be removed and implemented project level by overriding backend?
    # "SIGNIN_AUTOCREATE_ACCOUNT": True,
}

IMPORT_STRINGS: List[str] = []

api_settings = APISettings(getattr(settings, "DF_AUTH", IMPORT_STRINGS), DEFAULTS)
