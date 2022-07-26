from rest_framework import viewsets
from rest_framework.decorators import action
from rest_framework.settings import import_string
from rest_framework_simplejwt.settings import api_settings as sjwts
from rest_framework_simplejwt.views import TokenViewBase


class TokenViewSet(TokenViewBase, viewsets.GenericViewSet):
    @action(
        methods=["post"],
        detail=False,
        serializer_class=import_string(sjwts.TOKEN_REFRESH_SERIALIZER),
    )
    def refresh(self, request, *args, **kwargs):
        return self.post(request, *args, **kwargs)

    @action(
        methods=["post"],
        detail=False,
        serializer_class=import_string(sjwts.TOKEN_VERIFY_SERIALIZER),
    )
    def verify(self, request, *args, **kwargs):
        return self.post(request, *args, **kwargs)

    # @action(
    #     methods=["post"],
    #     detail=False,
    #     serializer_class=import_string(sjwts.TOKEN_BLACKLIST_SERIALIZER),
    # )
    # def blacklist(self, request, *args, **kwargs):
    #     return self.post(request, *args, **kwargs)
