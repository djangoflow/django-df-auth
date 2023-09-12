from typing import Any

from rest_framework.request import Request
from social_django.storage import BaseDjangoStorage
from social_django.strategy import DjangoStrategy


class DRFStrategy(DjangoStrategy):
    def __init__(self, storage: BaseDjangoStorage, request: Request) -> None:
        self.request = request
        super().__init__(storage, request)

    def request_data(self, merge: bool = True) -> Any:
        return self.request.data
