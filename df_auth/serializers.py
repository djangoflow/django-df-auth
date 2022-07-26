from django.contrib.auth import authenticate, get_user_model
from rest_framework import serializers

User = get_user_model()


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ("email",)  # has to be configurable or via get_fields()


class OTPField(serializers.CharField):
    pass


class TokenField(serializers.CharField):
    pass


class TokenObtainSerializer(UserSerializer):
    otp = OTPField(write_only=True, required=False)
    password = serializers.CharField(write_only=True, required=False)

    token = TokenField(read_only=True, source="_auth_token")
    user = UserSerializer(source="*")

    def validate(self, attrs):
        pass

    def save(self, **kwargs):
        self.instance = authenticate(
            request=self.context["request"], credentials=self.validated_data
        )
        # self.instance._auth_token =
