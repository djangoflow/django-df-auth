from typing import Any

from rest_framework.permissions import IsAuthenticated

from df_auth.settings import api_settings


class IsUnauthenticated(IsAuthenticated):
    def has_permission(self, *args: Any, **kwargs: Any) -> bool:
        return not super().has_permission(*args, **kwargs)


class IsUserCreateAllowed(IsAuthenticated):
    def has_permission(self, *args: Any, **kwargs: Any) -> bool:
        if super().has_permission(*args, **kwargs):
            return api_settings.INVITE_ALLOWED
        else:
            return api_settings.SIGNUP_ALLOWED
