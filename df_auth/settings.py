from django.conf import settings

#
# DEFAULTS = {
#     # Base API policies
#     'USER_IDENTITY_FIELDS': [
#         'email',
#     ],
# }

APP_SETTINGS = settings.get("DF_AUTH")
USER_IDENTITY_FIELDS = APP_SETTINGS["USER_IDENTITY_FIELDS"]
