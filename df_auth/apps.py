from django.apps import AppConfig
from django.utils.translation import gettext_lazy as _


class DFAuthConfig(AppConfig):
    default_auto_field = "hashid_field.BigHashidAutoField"
    api_path = "auth/"
    name = "df_auth"
    verbose_name = _("DjangoFlow Auth")

    def ready(self):
        try:
            import df_auth.signals  # noqa F401
        except ImportError:
            pass
