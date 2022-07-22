from rest_framework import viewsets, generics

from .serializers import TokenObtainSerializer


class TokenViewSet(generics.CreateAPIView, viewsets.GenericViewSet):
    serializer_class = TokenObtainSerializer
