DF_AUTH_APPS_BASE = [
    "df_auth",
    "rest_framework_simplejwt",
]

DF_AUTH_APPS_OTP = [
    "django_otp",
    "django_otp.plugins.otp_email",
    "django_otp.plugins.otp_totp",
    "django_otp.plugins.otp_static",
    "otp_twilio",
]

DF_AUTH_APPS_SOCIAL = [
    "social_django",
]

# Most common use case
DF_AUTH_INSTALLED_APPS = [
    *DF_AUTH_APPS_BASE,
    *DF_AUTH_APPS_OTP,
    *DF_AUTH_APPS_SOCIAL,
]
