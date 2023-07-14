from df_auth.models import PhoneNumberRule
from django.contrib import admin


@admin.register(PhoneNumberRule)
class PhoneNumberRulesAdmin(admin.ModelAdmin):
    list_display = (
        "id",
        "type",
        "number_regex",
    )
