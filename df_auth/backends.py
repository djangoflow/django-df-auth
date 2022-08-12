from .settings import api_settings
from django.contrib.auth import get_user_model
from django.contrib.auth.backends import ModelBackend
from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _
from django_otp.plugins.otp_email.models import EmailDevice


User = get_user_model()


class EmailOTPBackend(ModelBackend):
    @staticmethod
    def get_users(email):
        return User.objects.filter(is_active=True, email=email)

    def authenticate(self, request=None, email=None, otp=None, **kwargs):
        if email and otp:
            for user in self.get_users(email):
                if user.email == api_settings.TEST_USER_EMAIL:
                    return user
                if self.user_can_authenticate(user):
                    devices = EmailDevice.objects.filter(user=user)

                    if devices:
                        for device in devices.filter(confirmed=True):
                            if device.verify_token(otp):
                                updated_fields = []
                                if not getattr(
                                    user, api_settings.EMAIL_CONFIRMED_FIELD, True
                                ):
                                    setattr(
                                        user, api_settings.EMAIL_CONFIRMED_FIELD, True
                                    )
                                    updated_fields.append(
                                        api_settings.EMAIL_CONFIRMED_FIELD
                                    )

                                if (
                                    api_settings.OTP_EMAIL_UPDATE
                                    and device.email
                                    and user.email != device.email
                                ):
                                    user.email = device.email
                                    updated_fields.append("email")

                                if updated_fields:
                                    user.save(update_fields=updated_fields)

                                return user
                            raise ValidationError(
                                _("Wrong or expired one-time password")
                            )

    def generate_challenge(
        self, request=None, user=None, email=None, extra_context=None, **kwargs
    ):
        users = [user] if user else self.get_users(email)
        if email:
            for user in users:
                device = EmailDevice.objects.get_or_create(user=user, email=email)[0]
                device.generate_challenge(extra_context=extra_context)
        return users[0] if users and len(users) > 0 else None

    def register(self, request=None, email=None, extra_context=None, **kwargs):
        if self.get_users(email):
            raise ValidationError("User with this email is already registered")
        user, created = User._default_manager.get_or_create(
            email=email,
            first_name=kwargs.get("first_name", ""),
            last_name=kwargs.get("last_name", ""),
        )
        return user
