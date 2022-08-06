from django.conf import settings
from django.contrib.auth import authenticate
from django.contrib.auth import get_user_model
from django.contrib.auth.models import update_last_login
from django.utils.module_loading import import_string
from rest_framework import exceptions
from rest_framework import serializers
from rest_framework_simplejwt.settings import api_settings as simplejwt_settings
from social_core.exceptions import AuthCanceled, AuthForbidden
from social_django.utils import load_backend
from social_django.models import DjangoStorage
from ..settings import api_settings
from ..strategy import DRFStrategy

User = get_user_model()

AUTHENTICATION_BACKENDS = [
    import_string(backend) for backend in settings.AUTHENTICATION_BACKENDS
]


class AbstractIdentitySerializer(serializers.Serializer):
    user = None

    def get_fields(self):
        return super().get_fields() | {
            f: serializers.CharField(write_only=True, required=False)
            for f in api_settings.USER_IDENTITY_FIELDS
        }

    def validate_email(self, value):
        return User.objects.normalize_email(value)


class TokenCreateSerializer(serializers.Serializer):
    token = serializers.CharField(read_only=True)
    token_class = simplejwt_settings.AUTH_TOKEN_CLASSES[0]
    user = None

    @classmethod
    def get_token(cls, user):
        return cls.token_class.for_user(user)

    def validate(self, attrs):
        if not simplejwt_settings.USER_AUTHENTICATION_RULE(self.user):
            raise exceptions.AuthenticationFailed()

        token = self.get_token(self.user)

        attrs["token"] = str(token)

        if simplejwt_settings.UPDATE_LAST_LOGIN:
            update_last_login(None, self.user)

        return attrs


class TokenObtainSerializer(AbstractIdentitySerializer, TokenCreateSerializer):
    def validate(self, attrs):
        """
        Remove empty values to pass to authenticate or send_otp
        """
        attrs = {k: v for k, v in attrs.items() if v}
        self.user = authenticate(**attrs, **self.context)
        return super().validate(attrs)

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
        attrs = {k: v for k, v in attrs.items() if v}
        attrs = super().validate(attrs)
        for backend in AUTHENTICATION_BACKENDS:
            if hasattr(backend, "generate_challenge"):
                backend().generate_challenge(**attrs, **self.context)
        return attrs


class SocialTokenObtainSerializer(TokenCreateSerializer):
    access_token = serializers.CharField(write_only=True)
    provider = serializers.ChoiceField(
        choices=[
            (backend.name, backend.name)
            for backend in AUTHENTICATION_BACKENDS
            if hasattr(backend, "name")
        ],
        write_only=True,
    )

    response = serializers.JSONField(read_only=True)

    def validate(self, attrs):
        request = self.context["request"]
        request.social_strategy = DRFStrategy(DjangoStorage, request)
        request.backend = load_backend(request.social_strategy, attrs["provider"], redirect_uri=None)

        try:
            self.user = request.backend.do_auth(attrs['access_token'])
        except (AuthCanceled, AuthForbidden):
            raise exceptions.AuthenticationFailed()

        return super().validate(attrs)
