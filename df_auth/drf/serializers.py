from ..settings import api_settings
from ..strategy import DRFStrategy
from django.conf import settings
from django.contrib.auth import authenticate
from django.contrib.auth import get_user_model
from django.contrib.auth.models import update_last_login
from django.utils.module_loading import import_string
from itertools import chain
from rest_framework import exceptions
from rest_framework import serializers
from rest_framework_simplejwt.settings import api_settings as simplejwt_settings
from social_core.exceptions import AuthCanceled
from social_core.exceptions import AuthForbidden
from social_django.models import DjangoStorage
from social_django.utils import load_backend


User = get_user_model()

AUTHENTICATION_BACKENDS = [
    import_string(backend) for backend in settings.AUTHENTICATION_BACKENDS
]


class IdentitySerializerMixin(serializers.Serializer):
    user = None

    def get_fields(self):
        return super().get_fields() | {
            f: serializers.CharField(write_only=True, required=False)
            for f in api_settings.USER_IDENTITY_FIELDS
        }

    def validate_email(self, value):
        return User.objects.normalize_email(value)


class TokenSerializer(serializers.Serializer):
    token = serializers.CharField(read_only=True)
    token_class = simplejwt_settings.AUTH_TOKEN_CLASSES[0]
    user = None


class TokenCreateSerializer(TokenSerializer):
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


class TokenObtainSerializer(IdentitySerializerMixin, TokenCreateSerializer):
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


class AuthBackendSerializerMixin(IdentitySerializerMixin):
    backend_method_name = None

    def get_fields(self):
        return super().get_fields() | {
            f: serializers.CharField(write_only=True, required=False)
            for f in chain(
                api_settings.REQUIRED_AUTH_FIELDS, api_settings.OPTIONAL_AUTH_FIELDS
            )
        }

    def validate(self, attrs):
        attrs = {k: v for k, v in attrs.items() if v}
        attrs = super().validate(attrs)
        for backend in AUTHENTICATION_BACKENDS:
            if hasattr(backend, self.backend_method_name):
                self.user = getattr(backend(), self.backend_method_name)(
                    **attrs, **self.context
                )
                if self.user:
                    return attrs
        raise exceptions.AuthenticationFailed(
            "Authorization backend not found", code="not_found"
        )


class OTPObtainSerializer(AuthBackendSerializerMixin):
    backend_method_name = "generate_challenge"


class FirstLastNameSerializerMixin(serializers.Serializer):
    first_name = serializers.CharField(required=False)
    last_name = serializers.CharField(required=False)


class SocialTokenObtainSerializer(FirstLastNameSerializerMixin, TokenCreateSerializer):
    access_token = serializers.CharField(write_only=True)
    provider = serializers.ChoiceField(
        choices=[
            (backend.name, backend.name)
            for backend in AUTHENTICATION_BACKENDS
            if hasattr(backend, "name")
        ],
    )

    response = serializers.JSONField(read_only=True)

    def validate(self, attrs):
        request = self.context["request"]
        user = request.user if request.user.is_authenticated else None
        request.social_strategy = DRFStrategy(DjangoStorage, request)
        request.backend = load_backend(
            request.social_strategy, attrs["provider"], redirect_uri=None
        )

        try:
            self.user = request.backend.do_auth(attrs["access_token"], user=user)
        except (AuthCanceled, AuthForbidden):
            raise exceptions.AuthenticationFailed()

        update_fields = []
        for attr in ("first_name", "last_name"):
            if not getattr(self.user, attr, None):
                value = attrs.get(attr, None)
                if value:
                    setattr(self.user, attr, value)
                    update_fields.append(attr)
        if update_fields:
            self.user.save(update_fields=update_fields)

        return super().validate(attrs)


class SignupSerializer(FirstLastNameSerializerMixin, AuthBackendSerializerMixin):
    backend_method_name = "register"
    user = None
