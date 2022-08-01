from rest_framework_simplejwt.tokens import RefreshToken


def generate_jwt(user):
    """creates jwt token for user and returns as a dictionary like this:
    {
        'access_token': 'secure',
        'refresh_token': 'secure2',
    }
    """
    token = RefreshToken.for_user(user)
    return {
        'access_token': str(token.access_token),
        'refresh_token': str(token)
    }
