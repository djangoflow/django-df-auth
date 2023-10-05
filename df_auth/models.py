from django.conf import settings
from django.db import models


class UserOneToOneMixin(models.Model):
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
    )

    class Meta:
        abstract = True


class User2FA(UserOneToOneMixin):
    is_required = models.BooleanField(default=False)

    class Meta:
        verbose_name = "User 2FA"
        verbose_name_plural = "User 2FA"


class UserRegistration(UserOneToOneMixin):
    is_registering = models.BooleanField(default=True)
    invited_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="invitees",
        null=True,
        blank=True,
    )
