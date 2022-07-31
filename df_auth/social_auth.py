from django.conf import settings
from social_core.utils import get_strategy
from social_django.strategy import DjangoStrategy
from social_django.utils import psa
from social_django.utils import STORAGE


class DRFStrategy(DjangoStrategy):
    def __init__(self, storage, request=None, tpl=None):
        self.request = request
        super(DjangoStrategy, self).__init__(storage, tpl)

    def request_data(self):
        return self.request.data


def load_strategy(request=None):
    return get_strategy("df_auth.social_auth.DRFStrategy", STORAGE, request)


@psa(settings.REST_SOCIAL_OAUTH_REDIRECT_URI, load_strategy=load_strategy)
def decorate_request(request, backend):
    request.backend.STATE_PARAMETER = False
    request.backend.redirect_uri = settings.REST_SOCIAL_OAUTH_REDIRECT
