from django.utils.translation import gettext_lazy as _


class APIMessages:
    """API messages class
    Observer for storing all api endpoint messages
    """
    def __init__(self, *args, **kwargs):
        super(APIMessages, self).__init__(*args, **kwargs)

    @classmethod
    def get_message(cls, key):
        if not hasattr(cls, key):
            raise KeyError(key)
        return getattr(cls, key)

    PROVIDER_REQUIRED = _('Provider is required')
