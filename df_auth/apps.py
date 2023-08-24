from django.apps import AppConfig
from django.utils.translation import gettext_lazy as _


class DFAuthConfig(AppConfig):
    name = "df_auth"
    verbose_name = _("DjangoFlow Auth")

    class DFMeta:
        api_path = "auth/"
