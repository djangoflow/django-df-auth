from rest_framework import mixins, status, viewsets
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.settings import import_string
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError
from rest_framework_simplejwt.settings import api_settings as simplejwt_settings

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
