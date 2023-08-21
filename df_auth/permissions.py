from typing import Any

from rest_framework.permissions import IsAuthenticated


class IsUnauthenticated(IsAuthenticated):
    def has_permission(self, *args: Any, **kwargs: Any) -> bool:
        return not super().has_permission(*args, **kwargs)
