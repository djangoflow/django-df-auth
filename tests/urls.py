from django.contrib import admin
from django.urls import include
from django.urls import path


urlpatterns = [
    path("admin/", admin.site.urls),
    path("auth/", include("df_auth.drf.urls")),
]
