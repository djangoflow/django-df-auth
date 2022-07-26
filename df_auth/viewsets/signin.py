from django.utils.module_loading import import_string
from rest_framework import status, viewsets
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework_simplejwt.authentication import AUTH_HEADER_TYPES
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError

from ..serializers import TokenObtainSerializer


class SignInViewSet(viewsets.GenericViewSet):
    permission_classes = ()
    authentication_classes = ()

    serializer_class = None
    _serializer_class = ""

    www_authenticate_realm = "api"

    def get_serializer_class(self):
        """
        If serializer_class is set, use it directly. Otherwise get the class
        from settings.
        """

        if self.serializer_class:
            return self.serializer_class
        try:
            return import_string(self._serializer_class)
        except ImportError:
            msg = "Could not import serializer '%s'" % self._serializer_class
            raise ImportError(msg)

    def get_authenticate_header(self, request):
        return '{} realm="{}"'.format(
            AUTH_HEADER_TYPES[0],
            self.www_authenticate_realm,
        )

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
        serializer_class=TokenObtainSerializer,
    )
    def email(self, request, *args, **kwargs):
        return self._post(request, *args, **kwargs)
