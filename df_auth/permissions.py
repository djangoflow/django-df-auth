from rest_framework.permissions import IsAuthenticated


class IsUnauthenticated(IsAuthenticated):
    def has_permission(self, *args, **kwargs):
        return not super().has_permission(*args, **kwargs)
