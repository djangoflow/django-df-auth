from django.contrib.auth import authenticate, get_user_model
from rest_framework import serializers
from rest_framework.settings import import_string
from rest_framework_simplejwt.serializers import TokenObtainSerializer as __
from rest_framework_simplejwt.settings import api_settings as simplejwt_settings


class OTPField(serializers.CharField):
    pass


class TokenObtainSerializer(import_string(simplejwt_settings.TOKEN_OBTAIN_SERIALIZER)):
    otp = OTPField(write_only=True, required=False)
