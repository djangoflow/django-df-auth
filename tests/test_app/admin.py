from django.contrib import admin

from tests.test_app.models import User


@admin.register(User)
class UserAdmin(admin.ModelAdmin):
    search_fields = (
        "username",
        "id",
    )
    list_display = (
        "username",
        "email",
        "phone_number",
    )
