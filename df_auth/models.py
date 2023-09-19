from django.conf import settings
from django.db import models


class User2FA(models.Model):
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="user_2fa",
    )
    is_required = models.BooleanField(default=False)

    class Meta:
        verbose_name = "User 2FA"
        verbose_name_plural = "User 2FA"
