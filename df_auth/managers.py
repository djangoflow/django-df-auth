from typing import Any

from django.contrib.auth import get_user_model
from django.contrib.auth.base_user import BaseUserManager


class UserManager(BaseUserManager):
    def create_superuser(self, **extra_fields: Any) -> Any:
        """Create and save a SuperUser with the given email and password."""
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)

        if extra_fields.get("is_staff") is not True:
            raise ValueError("Superuser must have is_staff=True.")
        if extra_fields.get("is_superuser") is not True:
            raise ValueError("Superuser must have is_superuser=True.")

        return self._create_user(**extra_fields)

    def _create_user(self, **extra_fields: Any) -> Any:
        """Create and save a User with the given email and password."""
        User = get_user_model()
        password = extra_fields.pop("password", None)

        if not extra_fields.get(User.USERNAME_FIELD):
            raise ValueError(f"The given {User.USERNAME_FIELD} must be set")
        if User.EMAIL_FIELD in extra_fields:
            extra_fields[User.EMAIL_FIELD] = self.normalize_email(
                extra_fields[User.EMAIL_FIELD]
            )

        user = self.model(**extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_user(self, **extra_fields: Any) -> Any:
        """Create and save a regular User with the given email and password."""
        extra_fields.setdefault("is_staff", False)
        extra_fields.setdefault("is_superuser", False)
        return self._create_user(**extra_fields)
