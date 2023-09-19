from typing import Sequence

from django.contrib import admin, messages
from django.db.models import QuerySet
from django.http import HttpRequest
from django_otp.plugins.otp_email.models import EmailDevice
from otp_twilio.models import TwilioSMSDevice

from df_auth.models import User2FA
from df_auth.settings import api_settings


@admin.register(TwilioSMSDevice)
class TwilioSMSDeviceAdmin(admin.ModelAdmin):
    list_display = (
        "id",
        "name",
        "number",
        "user",
    )

    search_fields = (
        "name",
        "number",
    )
    autocomplete_fields = ("user",)

    @admin.action(description="Send challenge")
    def send_challenge(
        self, request: HttpRequest, queryset: QuerySet[TwilioSMSDevice]
    ) -> None:
        for device in queryset:
            device.generate_challenge()
            messages.success(request, f"{device.number}: {device.token}")

    actions = [send_challenge]


@admin.register(EmailDevice)
class EmailDeviceAdmin(admin.ModelAdmin):
    list_display = (
        "id",
        "name",
        "email",
        "user",
    )

    search_fields = (
        "name",
        "email",
    )
    autocomplete_fields = ("user",)

    @admin.action(description="Send challenge")
    def send_challenge(
        self, request: HttpRequest, queryset: QuerySet[EmailDevice]
    ) -> None:
        for device in queryset:
            device.generate_challenge()
            messages.success(request, f"{device.email}: {device.token}")

    actions = [send_challenge]


@admin.register(User2FA)
class User2FAAdmin(admin.ModelAdmin):
    list_display = ("user", "is_required")
    autocomplete_fields = ("user",)

    def get_search_fields(self, request: HttpRequest) -> Sequence[str]:
        return ["user__id"] + [
            f"user__{field}" for field in api_settings.USER_IDENTITY_FIELDS
        ]

    def enable(self, request: HttpRequest, queryset: QuerySet[User2FA]) -> None:
        queryset.update(is_required=True)
        messages.success(request, f"Enabled {queryset.count()} users")

    def disable(self, request: HttpRequest, queryset: QuerySet[User2FA]) -> None:
        queryset.update(is_required=False)
        messages.success(request, f"Disabled {queryset.count()} users")

    actions = [enable, disable]
