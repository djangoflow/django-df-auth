from df_auth.drf.serializers import SocialOAuth1TokenObtainSerializer
from df_auth.drf.serializers import SocialTokenObtainSerializer
from df_auth.drf.viewsets import SocialOAuth1TokenViewSet
from df_auth.strategy import DRFStrategy
from django.contrib.auth import get_user_model
from django.urls import reverse
from rest_framework.test import APIRequestFactory
from rest_framework.test import APITestCase
from rest_framework.test import force_authenticate
from social_django.models import DjangoStorage
from unittest.mock import MagicMock
from unittest.mock import patch

import json


User = get_user_model()


class SocialTokenObtainSerializerTests(APITestCase):
    """Tests for the SocialTokenObtainSerializer serializer."""

    def setUp(self):
        """Set up the test case by creating necessary test data and objects."""
        self.user = User.objects.create_user(
            email="testuser@example.com", password="testpassword"
        )
        # Create request object
        self.request = APIRequestFactory()
        self.request.user = self.user
        self.request.session = {}
        self.request.social_strategy = DRFStrategy(DjangoStorage, self.request)
        self.access_token = "test"

        self.serializer = SocialTokenObtainSerializer

    @patch("df_auth.drf.serializers.load_backend")
    def test_valid_data_oauth2(self, load_backend_mock):
        """Test that a valid social access token can be used to authenticate a user."""
        provider = "facebook"

        # Mock return values.
        backend = MagicMock()
        backend.name = provider
        load_backend_mock.return_value = backend
        mock_do_auth = backend.do_auth = MagicMock(return_value=self.user)

        valid_data = {
            "provider": "facebook",
            "access_token": self.access_token,
            "first_name": "John",
            "last_name": "Doe",
        }
        serializer = self.serializer(data=valid_data, context={"request": self.request})
        # Test to ensure no exception was raised.
        serializer.is_valid(raise_exception=True)

        # Ensure the mocked methods are called with the correspecting parameters.
        mock_do_auth.assert_called_once_with(self.access_token, user=self.user)
        load_backend_mock.assert_called_once_with(
            self.request.social_strategy, provider, redirect_uri=None
        )

        # Ensure the `token` key exist in the validated response
        self.assertIn("token", serializer.validated_data)


class SocialOAuth1TokenObtainSerializerTests(APITestCase):
    """Tests for the SocialTokenObtainSerializer serializer."""

    def setUp(self):
        """Set up the test case by creating necessary test data and objects."""
        self.user = User.objects.create_user(
            email="testuser@example.com", password="testpassword"
        )
        # Create request object
        self.request = APIRequestFactory()
        self.request.user = self.user
        self.request.session = {}
        self.request.social_strategy = DRFStrategy(DjangoStorage, self.request)

        self.serializer = SocialOAuth1TokenObtainSerializer

    @patch("df_auth.drf.serializers.load_backend")
    def test_valid_data_oauth1(self, load_backend_mock):
        """Test that a valid social oauth_token and oauth_token_secret can be used to authenticate a user."""
        provider = "twitter"
        oauth_token = "test"
        oauth_token_secret = "test2"

        # Mock return values.
        backend = MagicMock()
        backend.name = provider
        load_backend_mock.return_value = backend
        mock_do_auth = backend.do_auth = MagicMock(return_value=self.user)

        valid_data = {
            "provider": provider,
            "oauth_token": oauth_token,
            "oauth_token_secret": oauth_token_secret,
        }
        serializer = self.serializer(data=valid_data, context={"request": self.request})
        # Test to ensure no exception was raised.
        serializer.is_valid(raise_exception=True)

        # Ensure the mocked methods are called with the correspecting parameters.
        mock_do_auth.assert_called_once_with(
            {"oauth_token": oauth_token, "oauth_token_secret": oauth_token_secret},
            user=self.user,
        )
        load_backend_mock.assert_called_once_with(
            self.request.social_strategy, provider, redirect_uri=None
        )

        # Ensure the `token` key exist in the validated response
        self.assertIn("token", serializer.validated_data)


class SocialOAuth1TokenViewSetTests(APITestCase):
    def setUp(self):
        self.basic_user_info = {
            "email": "test@gmail.com",
            "first_name": "John",
            "last_name": "Doe",
        }
        self.factory = APIRequestFactory()
        self.provider = "twitter"
        self.user = User.objects.create(**self.basic_user_info)
        self.data = {
            "oauth_token": "test_token",
            "oauth_token_secret": "test_token_secret",
            "provider": self.provider,
        }

    def test_connect_authenticated(self):
        """Test an aunthenticated user accessing the endpoint."""
        request = self.factory.post(
            reverse("social_oauth1-connect"), data=self.data, format="json"
        )
        force_authenticate(request, user=self.user)
        response = SocialOAuth1TokenViewSet.as_view({"post": "connect"})(request)
        self.assertEqual(response.status_code, 403)

    @patch("df_auth.drf.serializers.load_backend")
    def test_connect_unauthenticated(self, mock_load_backend):
        """Test an unauthenticated user accessing the endpoint."""
        # Mock return values.
        backend = MagicMock(name=self.provider)
        mock_load_backend.return_value = backend
        backend.do_auth = MagicMock(return_value=self.user)

        request = self.factory.post(
            reverse("social_oauth1-connect"), data=self.data, format="json"
        )
        request.session = {}
        response = SocialOAuth1TokenViewSet.as_view({"post": "connect"})(request)
        self.assertEqual(response.status_code, 200)
        response.render()
        self.assertIn("token", json.loads(response.content))
