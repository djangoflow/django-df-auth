from django.conf import settings
from django.db import models


class UserOneToOneMixin:
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
    )


class User2FA(UserOneToOneMixin, models.Model):
    is_required = models.BooleanField(default=False)

    class Meta:
        verbose_name = "User 2FA"
        verbose_name_plural = "User 2FA"


class UserRegistration(UserOneToOneMixin, models.Model):
    is_registering = models.BooleanField(default=False)
    invited_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="invitees",
        null=True,
        blank=True,
    )
