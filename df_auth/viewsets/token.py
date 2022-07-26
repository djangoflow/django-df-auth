from rest_framework import mixins, viewsets
from rest_framework.decorators import action
from rest_framework.settings import import_string
from rest_framework_simplejwt.settings import api_settings as sjwts


class TokenViewSet(mixins.CreateModelMixin, viewsets.GenericViewSet):
    def perform_create(self, serializer):
        pass

    @action(
        methods=["post"],
        detail=False,
        serializer_class=import_string(sjwts.TOKEN_REFRESH_SERIALIZER),
    )
    def refresh(self, request, *args, **kwargs):
        return self.create(request, *args, **kwargs)

    @action(
        methods=["post"],
        detail=False,
        serializer_class=import_string(sjwts.TOKEN_VERIFY_SERIALIZER),
    )
    def verify(self, request, *args, **kwargs):
        return self.create(request, *args, **kwargs)

    # @action(
    #     methods=["post"],
    #     detail=False,
    #     serializer_class=import_string(sjwts.TOKEN_BLACKLIST_SERIALIZER),
    # )
    # def blacklist(self, request, *args, **kwargs):
    #     return self.create(request, *args, **kwargs)
