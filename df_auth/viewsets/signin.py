from rest_framework import mixins, viewsets
from rest_framework.decorators import action

from ..serializers import TokenObtainSerializer


class SignInViewSet(mixins.CreateModelMixin, viewsets.GenericViewSet):
    def perform_create(self, serializer):
        pass

    @action(
        methods=["post"],
        detail=False,
        serializer_class=TokenObtainSerializer,
    )
    def email(self, request, *args, **kwargs):
        return self.create(request, *args, **kwargs)
