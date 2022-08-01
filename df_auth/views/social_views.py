from df_auth.serializers import OAuth2UserJWTSerializer
from df_auth.views.base import BaseSocialView


class SocialLoginView(BaseSocialView):
    """
    class used for social authentications
    """
    response_serializer = OAuth2UserJWTSerializer