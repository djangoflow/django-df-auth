import environ

env = environ.Env()
environ.Env.read_env()

DF_AUTH_APPS = [
    'rest_framework',
    "df_auth",
    "rest_framework_simplejwt",
    "django_otp",
    "django_otp.plugins.otp_email",
    "django_otp.plugins.otp_totp",
    "django_otp.plugins.otp_static",
    "otp_twilio",
    "social_django",
]

AUTHENTICATION_BACKENDS = (
    'social_core.backends.google.GoogleOAuth2',
    'social_core.backends.github.GithubOAuth2',
    'social_core.backends.apple.AppleIdAuth',
    'social_core.backends.facebook.FacebookOAuth2',
    'django.contrib.auth.backends.ModelBackend',
)

SOCIAL_AUTH_RAISE_EXCEPTIONS = False

SOCIAL_AUTH_GOOGLE_OAUTH2_KEY = env('GOOGLE_OAUTH2_KEY')
SOCIAL_AUTH_GOOGLE_OAUTH2_SECRET = env('GOOGLE_OAUTH2_SECRET')
SOCIAL_AUTH_GITHUB_KEY = env('GITHUB_OAUTH2_KEY')
SOCIAL_AUTH_GITHUB_SECRET = env('GITHUB_OAUTH2_SECRET')
SOCIAL_AUTH_FACEBOOK_KEY = env('FACEBOOK_OAUTH2_KEY')
SOCIAL_AUTH_FACEBOOK_SECRET = env('FACEBOOK_OAUTH2_SECRET')
SOCIAL_AUTH_APPLE_ID_KEY = env('APPLE_ID_KEY')
SOCIAL_AUTH_APPLE_ID_SECRET = env('APPLE_ID_SECRET')
