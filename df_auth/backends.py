from .settings import api_settings
from django.contrib.auth import get_user_model
from django.contrib.auth.backends import ModelBackend
from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _
from django_otp.plugins.otp_email.models import EmailDevice
from otp_twilio.models import TwilioSMSDevice

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
                    devices = EmailDevice.objects.filter(user=user, email=email)
                    return self.authenticate_devices(devices, user, otp)

    def generate_challenge(
            self, request=None, user=None, email=None, extra_context=None, **kwargs
    ):
        if not email:
            return None

        if request.user.is_authenticated:
            device = EmailDevice.objects.filter(user=request.user, email=email).first()
            if not device and self.get_users(email):
                raise ValidationError(
                    _("User with this email is already exist")
                )
            users = [request.user]
        else:
            users = [user] if user else self.get_users(email)

        for user in users:
            device = EmailDevice.objects.get_or_create(user=user, email=email)[0]
            device.generate_challenge(extra_context=extra_context)
        return users[0] if users and len(users) > 0 else None

    def connect(self, request, email=None, otp=None, **kwargs):
        user = request.user
        if email and otp and self.user_can_authenticate(user):
            devices = EmailDevice.objects.filter(user=user, email=email, confirmed=True)
            return self.authenticate_devices(devices, user, otp)

    def authenticate_devices(self, devices, user, otp):
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

    def register(self, request=None, email=None, extra_context=None, **kwargs):
        if not email:
            return None
        if self.get_users(email):
            raise ValidationError("User with this email is already registered")
        user, created = User._default_manager.get_or_create(
            email=email,
            first_name=kwargs.get("first_name", ""),
            last_name=kwargs.get("last_name", ""),
        )
        return user

    def invite(self, email=None, **kwargs):
        if email:
            users = self.get_users(email)
            return users[0] if users else self.register(email=email, **kwargs)


class TwilioSMSOTPBackend(ModelBackend):
    @staticmethod
    def get_users(phone):
        return User.objects.filter(
            is_active=True, twiliosmsdevice__number=phone
        ).distinct()

    def authenticate(self, request=None, phone=None, otp=None, **kwargs):
        if phone and otp:
            for user in self.get_users(phone):
                if self.user_can_authenticate(user):
                    devices = TwilioSMSDevice.objects.filter(user=user)
                    return self.authenticate_devices(devices, user, otp)

    def generate_challenge(
            self, request=None, user=None, phone=None, extra_context=None, **kwargs
    ):
        if not phone:
            return None

        if request.user.is_authenticated:
            device = TwilioSMSDevice.objects.filter(user=request.user, number=phone).first()
            if not device and self.get_users(phone):
                raise ValidationError(
                    _("User with this phone is already exist")
                )
            users = [request.user]
        else:
            users = [user] if user else self.get_users(phone)

        for user in users:
            device = TwilioSMSDevice.objects.get_or_create(
                user=user, number=phone
            )[0]
            device.generate_challenge()
        return users[0] if users and len(users) > 0 else None

    def register(self, phone=None, **kwargs):
        if phone is None:
            return None

        if self.get_users(phone):
            raise ValidationError("User with this phone number is already registered")
        user = User._default_manager.create(
            first_name=kwargs.get("first_name", ""),
            last_name=kwargs.get("last_name", ""),
        )
        TwilioSMSDevice.objects.get_or_create(user=user, number=phone)
        return user

    def invite(self, phone=None, **kwargs):
        if phone:
            users = self.get_users(phone)
            return users[0] if users else self.register(phone=phone, **kwargs)

    def authenticate_devices(self, devices, user, otp):
        for device in devices.filter(confirmed=True):
            if device.verify_token(otp):
                if api_settings.PHONE_NUMBER_FIELD:
                    setattr(user, api_settings.PHONE_NUMBER_FIELD, device.number)
                    user.save(update_fields=[api_settings.PHONE_NUMBER_FIELD])
                return user
            raise ValidationError(
                _("Wrong or expired one-time password")
            )

    def connect(self, request=None, phone=None, otp=None, **kwargs):
        user = request.user
        if phone and otp and self.user_can_authenticate(user):
            devices = TwilioSMSDevice.objects.filter(user=user, number=phone, confirmed=True)
            return self.authenticate_devices(devices, user, otp)
