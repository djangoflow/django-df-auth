import os

from df_api_drf.defaults import (
    DF_API_DRF_INSTALLED_APPS,
    REST_FRAMEWORK,
    SPECTACULAR_SETTINGS,
)

from df_auth.defaults import DF_AUTH_INSTALLED_APPS

DEBUG = True

ROOT_URLCONF = "tests.urls"
SECRET_KEY = "111111"

DEFAULT_AUTO_FIELD = "django.db.models.AutoField"
AUTH_USER_MODEL = "test_app.User"

AUTHENTICATION_BACKENDS = [
    "df_auth.backends.TestEmailBackend",
    "df_auth.backends.TwilioSMSOTPBackend",
    "df_auth.backends.EmailOTPBackend",
    "django.contrib.auth.backends.ModelBackend",
    "social_core.backends.google.GoogleOAuth2",
    "social_core.backends.facebook.FacebookOAuth2",
    "social_core.backends.apple.AppleIdAuth",
    "social_core.backends.twitter.TwitterOAuth",
]

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.sites",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    *DF_API_DRF_INSTALLED_APPS,
    *DF_AUTH_INSTALLED_APPS,
    "tests.test_app.apps.TestAppConfig",
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
    "USER_IDENTITY_FIELDS": ("email", "phone_number"),
    "REQUIRED_AUTH_FIELDS": (),
    "OPTIONAL_AUTH_FIELDS": ("otp", "password"),
    "TEST_USER_EMAIL": "a@a.aa",
    "OTP_IDENTITY_UPDATE_FIELD": True,
}

OTP_TWILIO_ACCOUNT = os.environ.get("OTP_TWILIO_ACCOUNT", "")
OTP_TWILIO_AUTH = os.environ.get("OTP_TWILIO_AUTH", "")
OTP_TWILIO_FROM = os.environ.get("OTP_TWILIO_FROM", "")
OTP_TWILIO_TOKEN_VALIDITY = 300

EMAIL_HOST = os.environ.get("EMAIL_HOST", "")
EMAIL_PORT = os.environ.get("EMAIL_PORT", "")
EMAIL_USE_SSL = os.environ.get("EMAIL_USE_SSL", "")
EMAIL_HOST_USER = os.environ.get("EMAIL_HOST_USER", "")
EMAIL_HOST_PASSWORD = os.environ.get("EMAIL_HOST_PASSWORD", "")

SOCIAL_AUTH_TWITTER_KEY = os.environ.get("SOCIAL_AUTH_TWITTER_KEY", "")
SOCIAL_AUTH_TWITTER_SECRET = os.environ.get("SOCIAL_AUTH_TWITTER_SECRET", "")

SPECTACULAR_SETTINGS = {**SPECTACULAR_SETTINGS}

REST_FRAMEWORK = {**REST_FRAMEWORK}
REST_FRAMEWORK["DEFAULT_AUTHENTICATION_CLASSES"] += (
    "rest_framework.authentication.SessionAuthentication",
)
