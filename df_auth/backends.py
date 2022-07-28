from .serializers import api_settings
from django.contrib.auth import get_user_model
from django.contrib.auth.backends import ModelBackend
from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _
from django_otp.plugins.otp_email.models import EmailDevice


User = get_user_model()


class EmailOTPBackend(ModelBackend):
    @staticmethod
    def get_users(email):
        return User.objects.filter(is_active=True, email__iexact=email)

    def authenticate(self, request=None, email=None, otp=None, **kwargs):
        if email and otp:
            for user in self.get_users(email):
                if user.email == api_settings.TEST_USER_EMAIL:
                    return user
                if self.user_can_authenticate(user):
                    devices = EmailDevice.objects.filter(user=user)

                    if devices:
                        for device in devices:
                            if device.verify_token(otp):
                                if not user.get(
                                    api_settings.EMAIL_CONFIRMATION_FIELD, True
                                ):
                                    setattr(
                                        "api_settings.EMAIL_CONFIRMATION_FIELD", True
                                    )
                                    user.save(
                                        update_fields=[
                                            api_settings.EMAIL_CONFIRMATION_FIELD
                                        ]
                                    )

                            return user
                        raise ValidationError(_("Wrong or expired one-time password"))

    def generate_challenge(self, request=None, email=None, **kwargs):
        if email:
            for user in self.get_users(email):
                device = EmailDevice.objects.get_or_create(user=user)[0]
                device.generate_challenge()
