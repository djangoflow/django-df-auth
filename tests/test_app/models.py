from typing import List

from django.contrib.auth.models import AbstractUser
from django.db import models

from df_auth.managers import UserManager


class User(AbstractUser):
    objects = UserManager()  # type: ignore
    USERNAME_FIELD = "username"
    REQUIRED_FIELDS: List[str] = []
    email = models.EmailField(max_length=255, unique=True, null=True, blank=True)  # type: ignore
    phone_number = models.CharField(max_length=32, unique=True, null=True, blank=True)
