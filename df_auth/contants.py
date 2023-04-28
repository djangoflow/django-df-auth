from django.conf import settings
from django.utils.module_loading import import_string
from social_core.backends.oauth import BaseOAuth1
from social_core.backends.oauth import BaseOAuth2


AUTHENTICATION_BACKENDS = [
    import_string(backend) for backend in settings.AUTHENTICATION_BACKENDS
]

OAUTH2_BACKENDS_CHOICES = []
OAUTH1_BACKENDS_CHOICES = []

# Add supported providers to corresponding constants.
for backend in AUTHENTICATION_BACKENDS:
    if not hasattr(backend, "name"):
        continue

    # Add backends to corresponding choices.
    if isinstance(backend(), BaseOAuth1):
        OAUTH1_BACKENDS_CHOICES.append((backend.name, backend.name))
    elif isinstance(backend(), BaseOAuth2):
        OAUTH2_BACKENDS_CHOICES.append((backend.name, backend.name))
