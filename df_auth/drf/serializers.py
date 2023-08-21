from itertools import chain
from typing import Any, Dict, Optional

from django.contrib.auth import authenticate, get_user_model
from django.contrib.auth.models import AbstractUser, update_last_login
from rest_framework import exceptions, serializers
from rest_framework_simplejwt.settings import (
    api_settings as simplejwt_settings,
)
from social_core.exceptions import AuthCanceled, AuthForbidden
from social_django.models import DjangoStorage
from social_django.utils import load_backend

from df_auth.contants import (
    AUTHENTICATION_BACKENDS,
    OAUTH1_BACKENDS_CHOICES,
    OAUTH2_BACKENDS_CHOICES,
)

from ..settings import api_settings
from ..strategy import DRFStrategy

User = get_user_model()


class IdentitySerializerMixin(serializers.Serializer):
    user = None

    def get_fields(self) -> Dict[str, serializers.Field]:
        return super().get_fields() | {
            f: serializers.CharField(write_only=True, required=False, allow_blank=True)
            for f in api_settings.USER_IDENTITY_FIELDS
        }

    def validate_email(self, value: str) -> str:
        return User.objects.normalize_email(value)


class TokenSerializer(serializers.Serializer):
    token = serializers.CharField(read_only=True)
    token_class = simplejwt_settings.AUTH_TOKEN_CLASSES[0]
    user = None


class TokenCreateSerializer(TokenSerializer):
    @classmethod
    def get_token(cls, user: AbstractUser) -> None:
        return cls.token_class.for_user(user)

    def validate(self, attrs: Dict[str, Any]) -> Dict[str, Any]:
        if not simplejwt_settings.USER_AUTHENTICATION_RULE(self.user):
            raise exceptions.AuthenticationFailed()

        token = self.get_token(self.user)  # type: ignore

        attrs["token"] = str(token)

        if simplejwt_settings.UPDATE_LAST_LOGIN:
            update_last_login(None, self.user)  # type: ignore

        return attrs


class TokenObtainSerializer(IdentitySerializerMixin, TokenCreateSerializer):
    def validate(self, attrs: Dict[str, Any]) -> Dict[str, Any]:
        """
        Remove empty values to pass to authenticate or send_otp
        """
        attrs = {k: v for k, v in attrs.items() if v}
        self.user = authenticate(**attrs, **self.context)  # type: ignore
        return super().validate(attrs)

    def get_fields(self) -> Dict[str, serializers.Field]:
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
    backend_method_name: Optional[str] = None
    backend_extra_kwargs: Dict[str, Any] = {}

    def get_fields(self) -> Dict[str, serializers.Field]:
        return super().get_fields() | {
            f: serializers.CharField(write_only=True, required=False)
            for f in chain(
                api_settings.REQUIRED_AUTH_FIELDS, api_settings.OPTIONAL_AUTH_FIELDS
            )
        }

    def validate(self, attrs: Dict[str, Any]) -> Dict[str, Any]:
        attrs = {k: v for k, v in attrs.items() if v}
        attrs = super().validate(attrs)
        for backend in AUTHENTICATION_BACKENDS:
            if self.backend_method_name and hasattr(backend, self.backend_method_name):
                self.user = getattr(backend(), self.backend_method_name)(
                    **attrs, **self.backend_extra_kwargs, **self.context
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


class SocialTokenObtainBaseSerializer(
    FirstLastNameSerializerMixin, TokenCreateSerializer
):
    """Base serializer for obtaining social tokens."""

    response = serializers.JSONField(read_only=True)

    def validate(self, attrs: Dict[str, Any]) -> Dict[str, Any]:
        """Validate the serializer input and obtain the social token."""
        request = self.context["request"]
        user = request.user if request.user.is_authenticated else None
        request.social_strategy = DRFStrategy(DjangoStorage, request)
        access_token = attrs.get("access_token")

        # Construct access token dictionary for OAuth1
        if isinstance(self, SocialOAuth1TokenObtainSerializer):
            oauth_token = attrs["oauth_token"]
            oauth_token_secret = attrs["oauth_token_secret"]
            access_token = {
                "oauth_token": oauth_token,
                "oauth_token_secret": oauth_token_secret,
            }

        request.backend = load_backend(
            request.social_strategy, attrs["provider"], redirect_uri=None
        )

        try:
            self.user = request.backend.do_auth(access_token, user=user)
        except (AuthCanceled, AuthForbidden) as e:
            raise exceptions.AuthenticationFailed() from e

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


class SocialTokenObtainSerializer(SocialTokenObtainBaseSerializer):
    """Serializer for obtaining social tokens for OAuth2."""

    provider = serializers.ChoiceField(choices=OAUTH2_BACKENDS_CHOICES)
    access_token = serializers.CharField(write_only=True)


class SocialOAuth1TokenObtainSerializer(SocialTokenObtainBaseSerializer):
    """Serializer for obtaining social tokens for OAuth1."""

    provider = serializers.ChoiceField(choices=OAUTH1_BACKENDS_CHOICES)
    oauth_token = serializers.CharField(write_only=True)
    oauth_token_secret = serializers.CharField(write_only=True)


class SignupSerializer(FirstLastNameSerializerMixin, AuthBackendSerializerMixin):
    backend_method_name = "register"
    user = None


class InviteSerializer(FirstLastNameSerializerMixin, AuthBackendSerializerMixin):
    backend_method_name = "invite"
    user = None


class ConnectSerializer(FirstLastNameSerializerMixin, AuthBackendSerializerMixin):
    backend_method_name = "connect"
    user = None


class UnlinkSerializer(FirstLastNameSerializerMixin, AuthBackendSerializerMixin):
    backend_method_name = "unlink"
    user = None


class SetPasswordSerializer(AuthBackendSerializerMixin):
    backend_method_name = "set_password"
    user = None
