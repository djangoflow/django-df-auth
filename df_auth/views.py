from rest_framework.views import APIView
from rest_framework.response import Response

class DemoAPIView(APIView):
    def get(self, request):
        return Response({'demo':'demo'})
