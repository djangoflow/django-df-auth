import os

DEBUG = True

ROOT_URLCONF = "tests.urls"
SECRET_KEY = "111111"

DEFAULT_AUTO_FIELD = "django.db.models.AutoField"
AUTH_USER_MODEL = "test_app.User"

AUTHENTICATION_BACKENDS = [
    "df_auth.backends.TwilioSMSOTPBackend",
    "df_auth.backends.EmailOTPBackend",
    "django.contrib.auth.backends.ModelBackend",
    "social_core.backends.google.GoogleOAuth2",
    "social_core.backends.facebook.FacebookOAuth2",
    "social_core.backends.apple.AppleIdAuth",
]

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.sites",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "rest_framework",
    "tests.test_app.apps.TestAppConfig",

    "django_otp",
    "django_otp.plugins.otp_email",
    "django_otp.plugins.otp_totp",
    "django_otp.plugins.otp_static",
    "otp_twilio",
    "social_django",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
            "loaders": [
                "django.template.loaders.filesystem.Loader",
                "django.template.loaders.app_directories.Loader",
            ],
        },
    },
]

SITE_ID = 1

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": "db.sqlite3",
    }
}

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
        },
    },
    "root": {
        "handlers": ["console"],
        "level": "INFO",
    },
}

STATIC_URL = "/static/"

ALLOWED_HOSTS = ["*"]

DF_AUTH = {
    "USER_IDENTITY_FIELDS": ("email", "phone"),
    "REQUIRED_AUTH_FIELDS": (),
    "OPTIONAL_AUTH_FIELDS": ("otp", "password"),
    "TEST_USER_EMAIL": None,
    "EMAIL_CONFIRMED_FIELD": "email_confirmed",
    "OTP_EMAIL_UPDATE": True,
    "PHONE_NUMBER_FIELD": "phone_number",
}

OTP_TWILIO_ACCOUNT = os.environ.get('OTP_TWILIO_ACCOUNT', '')
OTP_TWILIO_AUTH = os.environ.get('OTP_TWILIO_AUTH', '')
OTP_TWILIO_FROM = os.environ.get('OTP_TWILIO_FROM', '')

EMAIL_HOST = os.environ.get("EMAIL_HOST", "")
EMAIL_PORT = os.environ.get("EMAIL_PORT", "")
EMAIL_USE_SSL = os.environ.get("EMAIL_USE_SSL", "")
EMAIL_HOST_USER = os.environ.get("EMAIL_HOST_USER", "")
EMAIL_HOST_PASSWORD = os.environ.get("EMAIL_HOST_PASSWORD", "")
