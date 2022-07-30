from social_django.strategy import DjangoStrategy


class DRFStrategy(DjangoStrategy):
    def __init__(self, storage, request=None, tpl=None):
        self.request = request
        super(DjangoStrategy, self).__init__(storage, tpl)

    def request_data(self):
        return self.request.data