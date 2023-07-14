from django.apps import AppConfig
from django.utils.translation import gettext_lazy as _


class DFAuthConfig(AppConfig):
    api_path = "auth/"
    name = "df_auth"
    verbose_name = _("DjangoFlow Auth")
