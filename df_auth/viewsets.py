from .serializers import OTPObtainSerializer
from .serializers import TokenObtainSerializer
from django.conf import settings
from rest_framework import permissions
from rest_framework import response
from rest_framework import status
from rest_framework import viewsets
from rest_framework.views import APIView
from rest_framework.decorators import action
from rest_framework.settings import import_string
from rest_framework_simplejwt.settings import api_settings as simple_jwt_settings

GOOGLE = 'google'


class ValidationOnlyCreateViewSet(viewsets.GenericViewSet):
    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        return response.Response(serializer.data, status=status.HTTP_200_OK)


class TokenViewSet(ValidationOnlyCreateViewSet):
    serializer_class = TokenObtainSerializer
    permission_classes = (permissions.AllowAny,)

    @action(
        methods=["post"],
        detail=False,
        serializer_class=import_string(simple_jwt_settings.TOKEN_REFRESH_SERIALIZER),
    )
    def refresh(self, request, *args, **kwargs):
        return self.create(request, *args, **kwargs)

    @action(
        methods=["post"],
        detail=False,
        serializer_class=import_string(simple_jwt_settings.TOKEN_VERIFY_SERIALIZER),
    )
    def verify(self, request, *args, **kwargs):
        return self.create(request, *args, **kwargs)

    @action(
        methods=["post"],
        detail=False,
        serializer_class=import_string(simple_jwt_settings.TOKEN_BLACKLIST_SERIALIZER),
    )
    def blacklist(self, request, *args, **kwargs):
        if "rest_framework_simplejwt.token_blacklist" not in settings.INSTALLED_APPS:
            raise NotImplementedError

        return self.create(request, *args, **kwargs)


class OTPViewSet(ValidationOnlyCreateViewSet):
    serializer_class = OTPObtainSerializer
    permission_classes = (permissions.AllowAny,)


class SignIn(APIView):
    permission_classes = []
    def post(self, request, social):
        if social == GOOGLE:
            return response.Response({})


class Connect(APIView):
    permission_classes = []
    def post(self, request, social):
        if social == GOOGLE:
            return response.Response({})


class CallBack(APIView):
    permission_classes = []
    def get(self, request):
        return response.Response({'code': request.GET['code']})
