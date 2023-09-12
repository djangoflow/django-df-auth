from datetime import timedelta

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

SIMPLE_JWT = {
    "ACCESS_TOKEN_LIFETIME": timedelta(days=14),
    "AUTH_HEADER_TYPES": ("Bearer",),
    "AUTH_TOKEN_CLASSES": ("rest_framework_simplejwt.tokens.SlidingToken",),
    "BLACKLIST_AFTER_ROTATION": False,
    "JTI_CLAIM": "jti",
    "REFRESH_TOKEN_LIFETIME": timedelta(days=14),
    "ROTATE_REFRESH_TOKENS": True,
    "SLIDING_TOKEN_LIFETIME": timedelta(days=14),
    "SLIDING_TOKEN_REFRESH_EXP_CLAIM": "refresh_exp",
    "SLIDING_TOKEN_REFRESH_LIFETIME": timedelta(days=14),
    "TOKEN_TYPE_CLAIM": "sliding",
    "USER_ID_CLAIM": "user_id",
    "USER_ID_FIELD": "id",
    "TOKEN_OBTAIN_SERIALIZER": "rest_framework_simplejwt.serializers.TokenObtainSlidingSerializer",
    "TOKEN_REFRESH_SERIALIZER": "rest_framework_simplejwt.serializers.TokenRefreshSlidingSerializer",
}

SOCIAL_AUTH_PIPELINE = [
    # Get the information we can about the user and return it in a simple
    # format to create the user instance later. On some cases the details are
    # already part of the auth response from the provider, but sometimes this
    # could hit a provider API.
    "social_core.pipeline.social_auth.social_details",
    # Get the social uid from whichever service we're authing thru. The uid is
    # the unique identifier of the given user in the provider.
    "social_core.pipeline.social_auth.social_uid",
    # Verifies that the current auth process is valid within the current
    # project, this is where emails and domains whitelists are applied (if
    # defined).
    # 'social_core.pipeline.social_auth.auth_allowed',
    # Checks if the current social-account is already associated in the site.
    "social_core.pipeline.social_auth.social_user",
    # Make up a username for this person, appends a random string at the end if
    # there's any collision.
    "social_core.pipeline.user.get_username",
    # Send a validation email to the user to verify its email address.
    # 'social_core.pipeline.mail.mail_validation',
    # Associates the current social details with another user account with
    # a similar email address.
    "social_core.pipeline.social_auth.associate_by_email",
    # Create a user account if we haven't found one yet.
    "social_core.pipeline.user.create_user",
    # Create the record that associated the social account with this user.
    "social_core.pipeline.social_auth.associate_user",
    # Populate the extra_data field in the social record with the values
    # specified by settings (and the default ones like access_token, etc).
    "social_core.pipeline.social_auth.load_extra_data",
    # Update the user record with any changed info from the auth service.
    "social_core.pipeline.user.user_details",
]
