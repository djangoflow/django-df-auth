from django.contrib import admin

from df_auth.models import PhoneNumberRule


@admin.register(PhoneNumberRule)
class PhoneNumberRulesAdmin(admin.ModelAdmin):
    list_display = (
        "id",
        "type",
        "number_regex",
    )
