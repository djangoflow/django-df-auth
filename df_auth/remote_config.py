from typing import Any, Optional

from df_remote_config.handlers import DefaultHandler
from django.conf import settings
from django.contrib.auth.backends import ModelBackend
from django.utils.module_loading import import_string

from df_auth.backends import BaseOTPBackend

AUTHENTICATION_BACKENDS = [
    import_string(backend) for backend in settings.AUTHENTICATION_BACKENDS
]

auth_schema = {
    "type": "object",
    "properties": {
        "providers": {
            "type": "object",
            "additionalProperties": {
                "type": "object",
                "properties": {
                    "button_text": {
                        "type": "string",
                    },
                    "redirect_uri": {
                        "type": "object",
                        "properties": {
                            "web": {"type": "string"},
                            "mobile": {"type": "string"},
                        },
                    },
                },
            },
        },
        "otp": {
            "type": "object",
            "properties": {
                "enabled": {
                    "type": "boolean",
                },
            },
        },
        "email_password": {
            "type": "object",
            "properties": {
                "enabled": {
                    "type": "boolean",
                },
            },
        },
    },
    "required": ["providers", "otp", "email_password"],
}


class AuthHandler(DefaultHandler):
    def get_part_data(self, part: Optional[Any]) -> dict:
        data = super().get_part_data(part)

        enabled_providers = [
            backend.name
            for backend in AUTHENTICATION_BACKENDS
            if hasattr(backend, "name")
        ]

        for provider in data["providers"]:
            if "enabled" not in data["providers"][provider]:
                data["providers"][provider]["enabled"] = provider in enabled_providers
            data["providers"][provider]["client_id"] = getattr(
                settings, f"SOCIAL_AUTH_{provider.upper()}_KEY", None
            )

        for provider in AUTHENTICATION_BACKENDS:
            if (
                issubclass(provider, ModelBackend)
                and "enabled" not in data["email_password"]
            ):
                data["email_password"].update(
                    {
                        "enabled": True,
                    }
                )
            if issubclass(provider, BaseOTPBackend) and "enabled" not in data["otp"]:
                data["otp"].update(
                    {
                        "enabled": True,
                    }
                )

        return data
