from django.contrib import admin
from tests.test_app.models import User


@admin.register(User)
class UserAdmin(admin.ModelAdmin):
    list_display = (
        "username",
        "email",
        "phone_number",
    )
