from rest_framework import status, viewsets
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError
from rest_framework_simplejwt.settings import api_settings as simplejwt_settings


class TokenViewSet(viewsets.GenericViewSet):
    def _post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)

        try:
            serializer.is_valid(raise_exception=True)
        except TokenError as e:
            raise InvalidToken(e.args[0])

        return Response(serializer.validated_data, status=status.HTTP_200_OK)

    @action(
        methods=["post"],
        detail=False,
        serializer_class=simplejwt_settings.TOKEN_REFRESH_SERIALIZER,
    )
    def refresh(self, request, *args, **kwargs):
        return self._post(request, *args, **kwargs)

    @action(
        methods=["post"],
        detail=False,
        serializer_class=simplejwt_settings.TOKEN_VERIFY_SERIALIZER,
    )
    def verify(self, request, *args, **kwargs):
        return self._post(request, *args, **kwargs)

    @action(
        methods=["post"],
        detail=False,
        serializer_class=simplejwt_settings.TOKEN_BLACKLIST_SERIALIZER,
    )
    def blacklist(self, request, *args, **kwargs):
        return self._post(request, *args, **kwargs)
