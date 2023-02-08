from django.contrib.auth.models import AbstractUser
from django.db import models


class User(AbstractUser):
    username = None
    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = []
    email = models.EmailField(max_length=255, unique=True, null=True)
    phone_number = models.CharField(max_length=32, null=True)
