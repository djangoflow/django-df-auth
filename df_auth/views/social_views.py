from rest_framework.permissions import IsAuthenticated


from df_auth.serializers import OAuth2UserJWTSerializer, OAuth2UserSerializer
from df_auth.views.base import BaseSocialView


class SocialLoginView(BaseSocialView):
    """
    class used for social authentications
    """
    response_serializer = OAuth2UserJWTSerializer

class SocialConnectView(BaseSocialView):
    """
    class used for social accounts connection
    """
    permission_classes = (IsAuthenticated,)
    response_serializer = OAuth2UserSerializer