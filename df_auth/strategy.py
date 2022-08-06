from social_django.strategy import DjangoStrategy


class DRFStrategy(DjangoStrategy):
    def __init__(self, storage, request):
        self.request = request
        super().__init__(storage, request)

    def request_data(self):
        return self.request.data
