from rest_framework.permissions import BasePermission


class IsUnauthenticated(BasePermission):
    def has_permission(self, request, view):
        return not request.user.is_authenticated
