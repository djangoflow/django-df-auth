from .settings import api_settings
from django.contrib.auth import authenticate
from django.contrib.auth.models import update_last_login
from rest_framework import exceptions
from rest_framework import serializers
from rest_framework_simplejwt.settings import api_settings as simplejwt_settings


class TokenObtainSerializer(serializers.Serializer):
    token = serializers.CharField(read_only=True)
    token_class = simplejwt_settings.AUTH_TOKEN_CLASSES[0]

    def validate(self, attrs):
        attrs = super().validate(attrs)
        self.user = authenticate(**attrs, **self.context)

        if not simplejwt_settings.USER_AUTHENTICATION_RULE(self.user):
            raise exceptions.AuthenticationFailed()

        token = self.get_token(self.user)

        attrs["token"] = str(token)

        if simplejwt_settings.UPDATE_LAST_LOGIN:
            update_last_login(None, self.user)

        return attrs

    @classmethod
    def get_token(cls, user):
        return cls.token_class.for_user(user)

    def get_fields(self):
        fields = super().get_fields()
        fields.update(
            {
                f: serializers.CharField(write_only=True, required=False)
                for f in api_settings.USER_IDENTITY_FIELDS
            }
        )
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
