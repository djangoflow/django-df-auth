from typing import Any, List, Optional

from django.contrib.auth.base_user import BaseUserManager
from django.contrib.auth.models import AbstractUser
from django.db import models


class UserManager(BaseUserManager):
    """Define a model manager for User model with no username field."""

    use_in_migrations = True

    @classmethod
    def normalize_email(cls, email: Optional[str]) -> str:
        return super().normalize_email(email).lower()

    def _create_user(
        self, email: str, password: str, **extra_fields: Any
    ) -> AbstractUser:
        """Create and save a User with the given email and password."""
        if not email:
            raise ValueError("The given email must be set")
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user  # type: ignore

    def create_user(
        self, username: str, password: str, **extra_fields: Any
    ) -> AbstractUser:
        """Create and save a regular User with the given email and password."""
        extra_fields.setdefault("is_staff", False)
        extra_fields.setdefault("is_superuser", False)
        return self._create_user(username, password, **extra_fields)

    def create_superuser(
        self, username: str, password: str, **extra_fields: Any
    ) -> AbstractUser:
        """Create and save a SuperUser with the given email and password."""
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)

        if extra_fields.get("is_staff") is not True:
            raise ValueError("Superuser must have is_staff=True.")
        if extra_fields.get("is_superuser") is not True:
            raise ValueError("Superuser must have is_superuser=True.")

        return self._create_user(username, password, **extra_fields)


class User(AbstractUser):
    objects = UserManager()  # type: ignore
    USERNAME_FIELD = "username"
    REQUIRED_FIELDS: List[str] = []
    email = models.EmailField(max_length=255, unique=True, null=True, blank=True)  # type: ignore
    phone_number = models.CharField(max_length=32, unique=True, null=True, blank=True)
    invited_by = models.ForeignKey(
        "self", on_delete=models.SET_NULL, null=True, blank=True
    )
