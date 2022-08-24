from django.conf import settings
from django.contrib.auth import get_user_model
from django.utils.module_loading import import_string
from rest_framework import status as http_status
from rest_framework.test import APITestCase
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework_simplejwt.settings import api_settings as simplejwt_settings
from unittest.mock import patch


User = get_user_model()

AUTHENTICATION_BACKENDS = [
    import_string(backend) for backend in settings.AUTHENTICATION_BACKENDS
]

token_class = simplejwt_settings.AUTH_TOKEN_CLASSES[0]


class TestTokenViewSet(APITestCase):
    user = None
    token = None
    matching_backends = []

    def setUp(self):
        self.matching_backends = [backend for backend in AUTHENTICATION_BACKENDS if hasattr(backend, "register")]
        self.user, created = User.objects.get_or_create(username="demo", email="demo@mail.com")
        self.user.set_password("pass")
        self.token = str(token_class.for_user(self.user))

    # for /token/refresh endpoint.
    # Check GET method is not allowed.
    def test_token_refresh_by_get_method(self):
        response = self.client.get("/token/refresh/")
        self.assertEqual(response.status_code, http_status.HTTP_405_METHOD_NOT_ALLOWED)

    # Check with POST method without arguments.
    def test_token_refresh_by_post_method_without_arguments(self):
        response = self.client.post("/token/refresh/")
        self.assertEqual(response.status_code, http_status.HTTP_400_BAD_REQUEST)

    # Check with POST method with empty arguments.
    def test_token_refresh_by_post_method_with_empty_arguments(self):
        payload = {
            "refresh": ""
        }
        response = self.client.post("/token/refresh/", data=payload)
        self.assertEqual(response.status_code, http_status.HTTP_400_BAD_REQUEST)

    # Check with POST method with wrong refresh token.
    def test_token_refresh_by_post_method_with_wrong_refresh_token(self):
        payload = {
            "refresh": "abcdefgh12345678"
        }
        with self.assertRaises(TokenError):
            self.client.post("/token/refresh/", data=payload)

    # Check with POST method with correct refresh token.
    @patch("rest_framework_simplejwt.serializers.TokenRefreshSerializer.validate")
    def test_token_refresh_by_post_method_with_correct_refresh_token(self, mock_validate):
        payload = {
            "refresh": "assumeitacorrectrefreshcode"
        }
        mock_validate.return_value = {
            "refresh": "assumeitacorrectrefreshcode",
            "access": self.token
        }
        response = self.client.post("/token/refresh/", data=payload)
        self.assertEqual(response.status_code, http_status.HTTP_200_OK)
        self.assertIn("refresh", response.data)
        self.assertIn("access", response.data)

    # for /token/verify endpoint.
    # Check GET method is not allowed.
    def test_token_verify_by_get_method(self):
        response = self.client.get("/token/verify/")
        self.assertEqual(response.status_code, http_status.HTTP_405_METHOD_NOT_ALLOWED)

    # Check with POST method without arguments.
    def test_token_verify_by_post_method_without_arguments(self):
        response = self.client.post("/token/verify/")
        self.assertEqual(response.status_code, http_status.HTTP_400_BAD_REQUEST)

    # Check with POST method with empty arguments.
    def test_token_verify_by_post_method_with_empty_arguments(self):
        payload = {
            "token": ""
        }
        response = self.client.post("/token/verify/", data=payload)
        self.assertEqual(response.status_code, http_status.HTTP_400_BAD_REQUEST)

    # Check with POST method with incorrect token.
    def test_token_verify_by_post_method_with_incorrect_token(self):
        payload = {
            "token": "abcdefgh12345678"
        }
        with self.assertRaises(TokenError):
            self.client.post("/token/verify/", data=payload)

    # Check with POST method with correct token.
    @patch("rest_framework_simplejwt.serializers.TokenVerifySerializer.validate")
    def test_token_verify_by_post_method_with_correct_token(self, mock_validate):
        payload = {
            "token": self.token
        }
        mock_validate.return_value = payload
        response = self.client.post("/token/verify/", data=payload)
        self.assertEqual(response.status_code, http_status.HTTP_200_OK)
        self.assertIn("token", response.data)

    # for /token/blacklist endpoint.
    # Check GET method is not allowed.
    def test_token_blacklist_by_get_method(self):
        response = self.client.get("/token/blacklist/")
        self.assertEqual(response.status_code, http_status.HTTP_405_METHOD_NOT_ALLOWED)

    # Check with POST method without arguments.
    def test_token_blacklist_by_post_method_without_arguments(self):
        if "rest_framework_simplejwt.token_blacklist" not in settings.INSTALLED_APPS:
            with self.assertRaises(NotImplementedError):
                self.client.post("/token/blacklist/")
        else:
            response = self.client.post("/token/blacklist/")
            self.assertEqual(response.status_code, http_status.HTTP_400_BAD_REQUEST)

    # Check with POST method with empty arguments.
    def test_token_blacklist_by_post_method_with_empty_arguments(self):
        payload = {
            "refresh": ""
        }
        if "rest_framework_simplejwt.token_blacklist" not in settings.INSTALLED_APPS:
            with self.assertRaises(NotImplementedError):
                self.client.post("/token/blacklist/", data=payload)
        else:
            response = self.client.post("/token/blacklist/", data=payload)
            self.assertEqual(response.status_code, http_status.HTTP_400_BAD_REQUEST)

    # Check with POST method with wrong argument.
    def test_token_blacklist_by_post_method_with_wrong_argument(self):
        payload = {
            "refresh": "abcdefgh12345678"
        }
        if "rest_framework_simplejwt.token_blacklist" not in settings.INSTALLED_APPS:
            with self.assertRaises(NotImplementedError):
                self.client.post("/token/blacklist/", data=payload)
        else:
            with self.assertRaises(TokenError):
                self.client.post("/token/blacklist/", data=payload)

    # Check with POST method with correct argument.
    @patch("rest_framework_simplejwt.serializers.TokenBlacklistSerializer.validate")
    def test_token_blacklist_by_post_method_with_correct_argument(self, mock_validate):
        payload = {
            "refresh": "assumeitacorrectrefreshcode"
        }
        mock_validate.return_value = payload
        if "rest_framework_simplejwt.token_blacklist" not in settings.INSTALLED_APPS:
            with self.assertRaises(NotImplementedError):
                self.client.post("/token/blacklist/", data=payload)
        else:
            response = self.client.post("/token/blacklist/", data=payload)
            self.assertEqual(response.status_code, http_status.HTTP_200_OK)
            self.assertIn("refresh", response.data)

    # for /token/signup endpoint.
    # Check GET method is not allowed.
    def test_token_signup_by_get_method(self):
        response = self.client.get("/token/signup/")
        self.assertEqual(response.status_code, http_status.HTTP_405_METHOD_NOT_ALLOWED)

    # Check with POST method without arguments.
    def test_token_signup_by_post_method_without_arguments(self):
        response = self.client.post("/token/signup/")
        if not self.matching_backends:
            self.assertEqual(response.status_code, http_status.HTTP_403_FORBIDDEN)
        else:
            self.assertEqual(response.status_code, http_status.HTTP_200_OK)

    # Check with POST method with only one empty argument.
    def test_token_signup_by_post_method_with_only_one_empty_argument1(self):
        payload = {
            "first_name": ""
        }
        response = self.client.post("/token/signup/", data=payload)
        if not self.matching_backends:
            self.assertEqual(response.status_code, http_status.HTTP_403_FORBIDDEN)
        else:
            self.assertEqual(response.status_code, http_status.HTTP_200_OK)

    # Check with POST method with only one empty argument.
    def test_token_signup_by_post_method_with_only_one_empty_argument2(self):
        payload = {
            "last_name": ""
        }
        response = self.client.post("/token/signup/", data=payload)
        if not self.matching_backends:
            self.assertEqual(response.status_code, http_status.HTTP_403_FORBIDDEN)
        else:
            self.assertEqual(response.status_code, http_status.HTTP_200_OK)

    # Check with POST method with both empty arguments.
    def test_token_signup_by_post_method_with_both_empty_arguments(self):
        payload = {
            "first_name": "",
            "last_name": ""
        }
        response = self.client.post("/token/signup/", data=payload)
        if not self.matching_backends:
            self.assertEqual(response.status_code, http_status.HTTP_403_FORBIDDEN)
        else:
            self.assertEqual(response.status_code, http_status.HTTP_200_OK)

    # Check with POST method with only first_name.
    def test_social_by_post_method_with_only_first_name(self):
        payload = {
            "first_name": "Rishi"
        }
        response = self.client.post("/token/signup/", data=payload)
        if not self.matching_backends:
            self.assertEqual(response.status_code, http_status.HTTP_403_FORBIDDEN)
        else:
            self.assertEqual(response.status_code, http_status.HTTP_200_OK)

    # Check with POST method with only last name.
    def test_social_by_post_method_with_only_last_name(self):
        payload = {
            "last_name": "Kumar"
        }
        response = self.client.post("/token/signup/", data=payload)
        if not self.matching_backends:
            self.assertEqual(response.status_code, http_status.HTTP_403_FORBIDDEN)
        else:
            self.assertEqual(response.status_code, http_status.HTTP_200_OK)

    # Check with POST method with only first_name and empty last_name.
    def test_social_by_post_method_with_only_first_name_and_empty_last_name(self):
        payload = {
            "first_name": "Rishi",
            "last_name": ""
        }
        response = self.client.post("/token/signup/", data=payload)
        if not self.matching_backends:
            self.assertEqual(response.status_code, http_status.HTTP_403_FORBIDDEN)
        else:
            self.assertEqual(response.status_code, http_status.HTTP_200_OK)

    # Check with POST method with only last_name and empty first_name.
    def test_social_by_post_method_with_only_last_name_and_empty_first_name(self):
        payload = {
            "first_name": "",
            "last_name": "Kumar"
        }
        response = self.client.post("/token/signup/", data=payload)
        if not self.matching_backends:
            self.assertEqual(response.status_code, http_status.HTTP_403_FORBIDDEN)
        else:
            self.assertEqual(response.status_code, http_status.HTTP_200_OK)

    # Check with POST method with both arguments.
    def test_social_by_post_method_with_both_arguments(self):
        payload = {
            "first_name": "Rishi",
            "last_name": "Kumar"
        }
        response = self.client.post("/token/signup/", data=payload)
        if not self.matching_backends:
            self.assertEqual(response.status_code, http_status.HTTP_403_FORBIDDEN)
        else:
            self.assertEqual(response.status_code, http_status.HTTP_200_OK)


class TestSocialTokenViewSet(APITestCase):
    user = None

    def setUp(self):
        self.user, created = User.objects.get_or_create(username="demo", email="demo@mail.com")
        self.user.set_password("pass")

    # for /social endpoint.
    # Check GET method is not allowed.
    def test_social_by_get_method(self):
        response = self.client.get("/social/")
        self.assertEqual(response.status_code, http_status.HTTP_405_METHOD_NOT_ALLOWED)

    # Check with POST method without arguments.
    def test_social_by_post_method_without_arguments(self):
        response = self.client.post("/social/")
        self.assertEqual(response.status_code, http_status.HTTP_400_BAD_REQUEST)

    # Check with POST method with only one empty argument.
    def test_social_by_post_method_with_only_one_empty_argument1(self):
        payload = {
            "access_token": ""
        }
        response = self.client.post("/social/", data=payload)
        self.assertEqual(response.status_code, http_status.HTTP_400_BAD_REQUEST)

    # Check with POST method with only one empty argument.
    def test_social_by_post_method_with_only_one_empty_argument2(self):
        payload = {
            "provider": ""
        }
        response = self.client.post("/social/", data=payload)
        self.assertEqual(response.status_code, http_status.HTTP_400_BAD_REQUEST)

    # Check with POST method with both empty arguments.
    def test_social_by_post_method_with_both_empty_arguments(self):
        payload = {
            "access_token": "",
            "provider": ""
        }
        response = self.client.post("/social/", data=payload)
        self.assertEqual(response.status_code, http_status.HTTP_400_BAD_REQUEST)

    # Check with POST method with only access_token.
    def test_social_by_post_method_with_only_access_token(self):
        payload = {
            "access_token": "abcdefgh12345678"
        }
        response = self.client.post("/social/", data=payload)
        self.assertEqual(response.status_code, http_status.HTTP_400_BAD_REQUEST)

    # Check with POST method with only correct provider.
    def test_social_by_post_method_with_only_currect_provider(self):
        payload = {
            "provider": "google-oauth2"
        }
        response = self.client.post("/social/", data=payload)
        self.assertEqual(response.status_code, http_status.HTTP_400_BAD_REQUEST)

    # Check with POST method with only incorrect provider.
    def test_social_by_post_method_with_only_incorrect_provider(self):
        payload = {
            "provider": "goooogle-ooaauth3"
        }
        response = self.client.post("/social/", data=payload)
        self.assertEqual(response.status_code, http_status.HTTP_400_BAD_REQUEST)

    # Check with POST method with access_token and incorrect provider.
    def test_social_by_post_method_with_access_token_and_incorrect_provider(self):
        payload = {
            "access_token": "abcdefgh12345678",
            "provider": "goooogle-ooaauth3"
        }
        response = self.client.post("/social/", data=payload)
        self.assertEqual(response.status_code, http_status.HTTP_400_BAD_REQUEST)

    # Check with POST method with incorrect access_token and correct provider.
    def test_social_by_post_method_with_incorrect_access_token_and_correct_provider(self):
        payload = {
            "access_token": "abcdefgh12345678",
            "provider": "google-oauth2"
        }
        response = self.client.post("/social/", data=payload)
        self.assertEqual(response.status_code, http_status.HTTP_403_FORBIDDEN)

    # Generate token using access_token provided by GoogleOAuth2
    @patch("social_core.backends.google.GoogleOAuth2.do_auth")
    def test_social_token_with_google_oauth2(self, mock_do_auth):
        post_data = {
            "access_token": "abcdefgh12345678",
            "provider": "google-oauth2"
        }
        mock_do_auth.return_value = self.user
        response = self.client.post("/social/", data=post_data)
        self.assertEqual(response.status_code, http_status.HTTP_200_OK)
        self.assertIn("token", response.data)

    # Generate token using access_token provided by FacebookOAuth2
    @patch("social_core.backends.facebook.FacebookOAuth2.do_auth")
    def test_social_token_with_facebook_oauth2(self, mock_do_auth):
        post_data = {
            "access_token": "abcdefgh12345678",
            "provider": "facebook"
        }
        mock_do_auth.return_value = self.user
        response = self.client.post("/social/", data=post_data)
        self.assertEqual(response.status_code, http_status.HTTP_200_OK)
        self.assertIn("token", response.data)

    # Generate token using access_token provided by AppleOAuth2
    @patch("social_core.backends.apple.AppleIdAuth.do_auth")
    def test_social_token_with_apple_id(self, mock_do_auth):
        post_data = {
            "access_token": "abcdefgh12345678",
            "provider": "apple-id"
        }
        mock_do_auth.return_value = self.user
        response = self.client.post("/social/", data=post_data)
        self.assertEqual(response.status_code, http_status.HTTP_200_OK)
        self.assertIn("token", response.data)
