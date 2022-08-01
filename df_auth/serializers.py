from .settings import api_settings
from .social_auth import authenticate_or_connect
from django.conf import settings
from django.contrib.auth import authenticate
from django.contrib.auth import get_user_model
from django.contrib.auth.models import update_last_login
from django.utils.module_loading import import_string
from rest_framework import exceptions
from rest_framework import serializers
from rest_framework_simplejwt.settings import api_settings as simplejwt_settings


User = get_user_model()


class AbstractIdentitySerializer(serializers.Serializer):
    user = None

    def get_fields(self):
        return super().get_fields() | {
            f: serializers.CharField(write_only=True, required=False)
            for f in api_settings.USER_IDENTITY_FIELDS
        }

    def validate_email(self, value):
        return User.objects.normalize_email(value)

    def validate(self, attrs):
        """
        Remove empty values to pass to authenticate or send_otp
        """
        return {k: v for k, v in attrs.items() if v}


class AbstractTokenSerializer(serializers.Serializer):
    token = serializers.CharField(read_only=True)
    token_class = simplejwt_settings.AUTH_TOKEN_CLASSES[0]

    @classmethod
    def get_token(cls, user):
        token = cls.token_class.for_user(user)
        if simplejwt_settings.UPDATE_LAST_LOGIN:
            update_last_login(None, user)
        return token


class TokenObtainSerializer(AbstractTokenSerializer, AbstractIdentitySerializer):
    def validate(self, attrs):
        attrs = super().validate(attrs)
        self.user = authenticate(**attrs, **self.context)

        if not simplejwt_settings.USER_AUTHENTICATION_RULE(self.user):
            raise exceptions.AuthenticationFailed()

        attrs["token"] = str(self.get_token(self.user))
        return attrs

    def get_fields(self):
        fields = super().get_fields()
        if api_settings.REQUIRED_AUTH_FIELDS:
            fields.update(
                {
                    f: serializers.CharField(write_only=True, required=True)
                    for f in api_settings.REQUIRED_AUTH_FIELDS
                }
            )

        if api_settings.OPTIONAL_AUTH_FIELDS:
            fields.update(
                {
                    f: serializers.CharField(write_only=True, required=False)
                    for f in api_settings.OPTIONAL_AUTH_FIELDS
                }
            )
        return fields


class OTPObtainSerializer(AbstractIdentitySerializer):
    def get_fields(self):
        return super().get_fields() | {
            f: serializers.CharField(write_only=True, required=False)
            for f in zip(
                api_settings.REQUIRED_AUTH_FIELDS, api_settings.OPTIONAL_AUTH_FIELDS
            )
        }

    def validate(self, attrs):
        attrs = super().validate(attrs)
        for backend in settings.AUTHENTICATION_BACKENDS:
            backend_module = import_string(backend)
            if hasattr(backend_module, "generate_challenge"):
                backend_module().generate_challenge(**attrs, **self.context)

        return attrs


class AbstractSocialIdentitySerializer(serializers.Serializer):
    user = None
    provider = serializers.CharField(write_only=True)
    code = serializers.CharField(write_only=True)


class SocialTokenObtainSerializer(
    AbstractTokenSerializer, AbstractSocialIdentitySerializer
):
    def validate(self, attrs):
        request = self.context["request"]
        self.user = authenticate_or_connect(request, attrs, None)
        if not simplejwt_settings.USER_AUTHENTICATION_RULE(self.user):
            raise exceptions.AuthenticationFailed()
        attrs["token"] = str(self.get_token(self.user))
        return attrs


class SocialConnectSerializer(
    AbstractTokenSerializer, AbstractSocialIdentitySerializer
):
    def validate(self, attrs):
        request = self.context["request"]
        self.user = request.user
        authenticate_or_connect(request, attrs, self.user)
        if not simplejwt_settings.USER_AUTHENTICATION_RULE(self.user):
            raise exceptions.AuthenticationFailed()
        attrs["token"] = str(self.get_token(self.user))
        return attrs


class SocialCallBackSerializer(serializers.Serializer):
    code = serializers.CharField()
