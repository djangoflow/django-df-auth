from django.urls import path
from .views import PaaView

urlpatterns = [
    path('paa/', PaaView.as_view()),
]
