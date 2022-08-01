from urllib.error import HTTPError
from urllib.parse import urlparse, urljoin

from django.conf import settings
from django.http import HttpResponse
from django.utils.encoding import iri_to_uri

from rest_framework import status
from rest_framework.exceptions import ValidationError
from rest_framework.generics import GenericAPIView
from rest_framework.permissions import AllowAny
from rest_framework.response import Response

from social_core.exceptions import AuthException
from social_core.utils import user_is_authenticated, setting_name
from social_django.utils import psa, load_strategy

from df_auth.messages import APIMessages
from df_auth.serializers import OAuth2InputSerializer

# TODO: Change setting names
REDIRECT_URI = getattr(settings, 'REST_SOCIAL_OAUTH_REDIRECT_URI', '/')
DOMAIN_FROM_ORIGIN = True
STRATEGY = getattr(settings, setting_name('STRATEGY'), 'df_auth.strategy.DRFStrategy')


@psa(REDIRECT_URI, load_strategy=load_strategy)
def decorate_request(request, backend):
    pass


class BaseSocialView(GenericAPIView):
    """Social authentication base view
    uses python-social-auth for authentication
    passes user to response_serializer can be implemented in subclass
    """
    permission_classes = (AllowAny,)
    serializer_class = OAuth2InputSerializer
    response_serializer = None
    allowed_backends = None

    @staticmethod
    def __get_redirect_uri(manual_redirect_uri):
        """get redirect_uri from input data or from settings"""
        if not manual_redirect_uri:
            manual_redirect_uri = getattr(
                settings, 'REST_SOCIAL_OAUTH_ABSOLUTE_REDIRECT_URI', None)
        return manual_redirect_uri

    @staticmethod
    def __error_response(error):
        """return error response"""
        return Response({'error': error}, status=status.HTTP_400_BAD_REQUEST)

    def __get_provider_name(self, input_data):
        """get provider name from input data"""
        if self.kwargs.get('provider'):
            return self.kwargs['provider']
        return input_data.get('provider')

    def __validate_allowed_backends(self, provider_name):
        """validate if provider is allowed"""
        if self.allowed_backends and provider_name not in self.allowed_backends:
            raise ValidationError('Provider is not allowed: %s' % provider_name)

    def __set_auth_data(self, data):
        """set auth data to request"""
        self.request.auth_data = data

    def get_object(self):
        """get/create user from social auth backend"""
        user = self.request.user
        manual_redirect_uri = self.request.auth_data.pop('redirect_uri', None)
        manual_redirect_uri = self.__get_redirect_uri(manual_redirect_uri)
        if manual_redirect_uri:
            self.request.backend.redirect_uri = manual_redirect_uri
        elif DOMAIN_FROM_ORIGIN:
            origin = self.request.strategy.request.META.get('HTTP_ORIGIN')
            if origin:
                relative_path = urlparse(self.request.backend.redirect_uri).path
                url = urlparse(origin)
                origin_scheme_host = "%s://%s" % (url.scheme, url.netloc)
                location = urljoin(origin_scheme_host, relative_path)
                self.request.backend.redirect_uri = iri_to_uri(location)
        is_authenticated = user_is_authenticated(user)
        user = user if is_authenticated else None
        self.request.backend.REDIRECT_STATE = False
        self.request.backend.STATE_PARAMETER = False
        user = self.request.backend.complete(user=user)
        return user

    def post(self, request, *args, **kwargs):
        input_data = request.data.copy()
        provider_name = self.__get_provider_name(input_data)
        if not provider_name:
            return self.__error_response(APIMessages.get_message('PROVIDER_REQUIRED'))
        self.__validate_allowed_backends(provider_name)
        self.__set_auth_data(input_data)
        decorate_request(request, provider_name)
        serializer_in = self.serializer_class(data=input_data)
        serializer_in.is_valid(raise_exception=True)

        try:
            # do authentication and retrieve/register user
            user = self.get_object()
        except (AuthException, HTTPError) as e:
            return self.__error_response(str(e))

        if isinstance(user, HttpResponse):
            # error happened and pipeline returned HttpResponse instead of user
            return user

        response_serializer = self.response_serializer(instance=user)
        return Response(response_serializer.data)
