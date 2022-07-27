import rest_framework_simplejwt.settings
from rest_framework import serializers
from rest_framework.settings import import_string

# from rest_framework_simplejwt.views import *


class OTPField(serializers.CharField):
    pass


class TokenObtainSerializer(
    import_string(
        rest_framework_simplejwt.settings.api_settings.TOKEN_OBTAIN_SERIALIZER
    )
):
    otp = OTPField(write_only=True, required=False)
