from django.contrib import admin, messages
from django.db.models import QuerySet
from django.http import HttpRequest
from django_otp.plugins.otp_email.models import EmailDevice
from otp_twilio.models import TwilioSMSDevice


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
