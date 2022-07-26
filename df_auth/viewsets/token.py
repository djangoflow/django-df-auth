from rest_framework import mixins, status, viewsets
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.settings import import_string
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError
from rest_framework_simplejwt.settings import api_settings as simplejwt_settings


class TokenViewSet(mixins.CreateModelMixin, viewsets.GenericViewSet):
    def perform_create(self, serializer):
        pass

    @action(
        methods=["post"],
        detail=False,
        serializer_class=import_string(simplejwt_settings.TOKEN_REFRESH_SERIALIZER),
    )
    def refresh(self, request, *args, **kwargs):
        return self.create(request, *args, **kwargs)

    @action(
        methods=["post"],
        detail=False,
        serializer_class=import_string(simplejwt_settings.TOKEN_VERIFY_SERIALIZER),
    )
    def verify(self, request, *args, **kwargs):
        return self.create(request, *args, **kwargs)

    # @action(
    #     methods=["post"],
    #     detail=False,
    #     serializer_class=import_string(simplejwt_settings.TOKEN_BLACKLIST_SERIALIZER),
    # )
    # def blacklist(self, request, *args, **kwargs):
    #     return self.create(request, *args, **kwargs)
