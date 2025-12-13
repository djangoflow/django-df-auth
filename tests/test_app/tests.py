import json

import httpretty
import pytest
from django.db import IntegrityError
from django_otp.plugins.otp_email.models import EmailDevice
from django_otp.plugins.otp_totp.models import TOTPDevice
from otp_twilio.models import TwilioSMSDevice
from rest_framework import status
from rest_framework.test import APIClient, APITestCase

from df_auth.exceptions import UserDoesNotExistError
from df_auth.models import User2FA
from df_auth.settings import DEFAULTS, api_settings
from tests.test_app.models import User

pytestmark = pytest.mark.django_db


class OtpDeviceViewSetAPITest(APITestCase):
    def setUp(self) -> None:
        # Create a test user and set up any other objects you need
        self.user = User.objects.create_user(username="testuser", password="testpass")
        self.client = APIClient()
        self.client.force_authenticate(user=self.user)
        self.email = "test@te.st"
        self.phone_number = "+1234567890"

    def test_create_email_device(self) -> None:
        # Define the URL and the payload

        # Make the API request to create a new email Device
        response = self.client.post(
            "/api/v1/auth/otp-devices/",
            {
                "type": "email",
                "name": self.email,
            },
        )

        # Check that the response indicates success
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data["name"], self.email)

        # Check that a Device object was actually created
        device = EmailDevice.objects.filter(
            user=self.user,
            name=self.email,
        ).first()
        self.assertIsNotNone(device)
        # Check that it's not verified
        self.assertFalse(device.confirmed)
        self.assertEqual(device.email, self.email)

    def test_create_totp_device(self) -> None:
        response = self.client.post(
            "/api/v1/auth/otp-devices/",
            {
                "type": "totp",
                "name": "totp",
            },
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        # Check that a key was returned
        device = TOTPDevice.objects.filter(user=self.user).first()
        self.assertIsNotNone(device)
        self.assertEqual(response.data["type"], "totp")
        self.assertIn("url", response.data["extra_data"])
        self.assertEqual(device.config_url, response.data["extra_data"]["url"])

        # Check we will not return the URL again
        response = self.client.get("/api/v1/auth/otp-devices/")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data["results"]), 1)
        self.assertEqual(response.data["results"][0]["type"], "totp")
        self.assertNotIn("url", response.data["results"][0]["extra_data"])

    def test_confirm_email_device(self) -> None:
        email_device = EmailDevice.objects.create(
            user=self.user,
            name=self.email,
            email=self.email,
            confirmed=False,
        )
        self.assertIsNone(email_device.token)

        response = self.client.post(
            "/api/v1/auth/otp/",
            {
                "email": email_device.email,
            },
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        email_device.refresh_from_db()
        self.assertIsNotNone(email_device.token)

        response = self.client.post(
            f"/api/v1/auth/otp-devices/{email_device.pk}/confirm/?type=email",
            {"otp": "wrong-token"},
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        email_device.refresh_from_db()
        self.assertFalse(email_device.confirmed)
        email_device.throttle_reset(commit=True)

        self.user.refresh_from_db()
        self.assertIsNone(self.user.email)
        response = self.client.post(
            f"/api/v1/auth/otp-devices/{email_device.pk}/confirm/?type=email",
            {"otp": email_device.token},
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        email_device.refresh_from_db()
        self.assertTrue(email_device.confirmed)
        self.user.refresh_from_db()
        self.assertEqual(self.user.email, self.email)

    def test_destroy_email_device(self) -> None:
        email_device = EmailDevice.objects.create(
            user=self.user,
            name=self.email,
            confirmed=True,
        )

        response = self.client.get("/api/v1/auth/otp-devices/")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data["results"]), 1)
        self.assertEqual(response.data["results"][0]["name"], self.email)
        self.assertEqual(response.data["results"][0]["type"], "email")

        response = self.client.delete(
            f"/api/v1/auth/otp-devices/{email_device.pk}/?type=email"
        )
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)

        response = self.client.get("/api/v1/auth/otp-devices/")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data["results"]), 0)

    def test_list_device_with_different_types(self) -> None:
        EmailDevice.objects.create(
            user=self.user,
            name=self.email,
        )
        TwilioSMSDevice.objects.create(
            user=self.user,
            name=self.phone_number,
        )
        TOTPDevice.objects.create(
            user=self.user,
            name="default",
        )
        response = self.client.get("/api/v1/auth/otp-devices/")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data["results"]), 3)
        types = [device["type"] for device in response.data["results"]]
        self.assertIn("email", types)
        self.assertIn("sms", types)
        self.assertIn("totp", types)


class UserViewSetAPITest(APITestCase):
    def setUp(self) -> None:
        # Create a test user and set up any other objects you need
        self.client = APIClient()
        self.email = "test@te.st"
        self.phone_number = "+31612345678"
        self.password = "passwd"

    def test_create_user_with_email_password(self) -> None:
        response = self.client.post(
            "/api/v1/auth/users/",
            {
                "email": self.email,
                "password": self.password,
            },
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data["email"], self.email)
        self.assertNotIn("password", response.data)

        user = User.objects.get(email=self.email)
        self.assertTrue(user.check_password(self.password))
        self.assertEqual(user.username, self.email)

        device = EmailDevice.objects.get(user=user, name=self.email)
        self.assertFalse(device.confirmed)

    def test_retrieve_user(self) -> None:
        user = User.objects.create_user(
            username=self.email,
            email=self.email,
            password=self.password,
        )
        client = APIClient()
        client.force_authenticate(user=user)

        response = client.get(
            "/api/v1/auth/users/0/",
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["email"], self.email)
        self.assertNotIn("password", response.data)

    def test_user_invites_user_by_email_phone(self) -> None:
        user_1 = User.objects.create_user(username="testuser", password="testpass")
        client = APIClient()
        client.force_authenticate(user=user_1)

        email_2 = "test2@te.st"
        phone_2 = "+31645427185"

        response = client.post(
            "/api/v1/auth/users/",
            {
                "phone_number": phone_2,
                "email": email_2,
            },
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data["phone_number"], phone_2)

        user_2 = User.objects.get(phone_number=phone_2)
        self.assertEqual(user_2.userregistration.invited_by, user_1)
        phone_device = TwilioSMSDevice.objects.get(user=user_2, name=phone_2)
        self.assertFalse(phone_device.confirmed)
        email_device = EmailDevice.objects.get(user=user_2, name=email_2)
        self.assertFalse(email_device.confirmed)

    def test_user_nl_phone_strips_zero(self) -> None:
        response = self.client.post(
            "/api/v1/auth/users/",
            {
                "phone_number": "+310612345678",
                "email": "test2@te.st",
            },
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data["phone_number"], "+31612345678")  # 0 stripped

    def test_user_can_update_first_name(self) -> None:
        user = User.objects.create_user(username="testuser", password="testpass")
        client = APIClient()
        client.force_authenticate(user=user)

        response = client.patch(
            "/api/v1/auth/users/0/",
            {
                "first_name": "test",
            },
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["first_name"], "test")

    def test_user_cannot_update_phone_number_if_not_verified(self) -> None:
        user = User.objects.create_user(username="testuser", password="testpass")
        client = APIClient()
        client.force_authenticate(user=user)

        response = client.patch(
            "/api/v1/auth/users/0/",
            {
                "phone_number": self.phone_number,
            },
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data["errors"][0]["code"], "invalid")

    def test_user_can_update_phone_number_if_verified(self) -> None:
        user = User.objects.create_user(username="testuser", password="testpass")
        client = APIClient()
        client.force_authenticate(user=user)

        TwilioSMSDevice.objects.create(
            user=user,
            name=self.phone_number,
            number=self.phone_number,
            confirmed=True,
        )

        response = client.patch(
            "/api/v1/auth/users/0/",
            {
                "phone_number": self.phone_number,
            },
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["phone_number"], self.phone_number)

    def test_set_password_wrong_old_password_raises_error(self) -> None:
        user = User.objects.create_user(username="testuser", password="testpass")
        client = APIClient()
        client.force_authenticate(user=user)

        response = client.post(
            "/api/v1/auth/users/0/set-password/",
            {
                "old_password": "wrong",
                "new_password": "new",
            },
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data["errors"][0]["code"], "invalid")

    def test_set_password_correct_old_password_sets_new_password(self) -> None:
        user = User.objects.create_user(username="testuser", password="testpass")
        client = APIClient()
        client.force_authenticate(user=user)

        response = client.post(
            "/api/v1/auth/users/0/set-password/",
            {
                "old_password": "testpass",
                "new_password": "new",
            },
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(user.check_password("new"))

    def test_user_cannot_signup_if_email_already_taken(self) -> None:
        User.objects.create_user(
            username="testuser", password="testpass", email=self.email
        )
        response = self.client.post(
            "/api/v1/auth/users/",
            {
                "email": self.email,
                "password": "testpass",
            },
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data["errors"][0]["code"], "invalid")

    def test_user_cannot_signup_if_phone_number_already_taken(self) -> None:
        User.objects.create_user(
            username="testuser", password="testpass", phone_number=self.phone_number
        )
        response = self.client.post(
            "/api/v1/auth/users/",
            {
                "phone_number": self.phone_number,
                "password": "testpass",
            },
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data["errors"][0]["code"], "invalid")


class UserViewSetWithUsernameOnlyIdentityFieldAPITest(APITestCase):
    def setUp(self) -> None:
        self.client = APIClient()
        self.email = "test@te.st"
        self.phone_number = "+31612345678"
        api_settings.USER_IDENTITY_FIELDS = {
            "username": "rest_framework.serializers.CharField",
        }
        api_settings.USER_OPTIONAL_FIELDS = {
            "first_name": "rest_framework.serializers.CharField",
            "last_name": "rest_framework.serializers.CharField",
            "password": "rest_framework.serializers.CharField",
            "email": "rest_framework.serializers.CharField",
            "phone_number": "phonenumber_field.serializerfields.PhoneNumberField",
        }

    def tearDown(self) -> None:
        api_settings.USER_IDENTITY_FIELDS = DEFAULTS["USER_IDENTITY_FIELDS"]
        api_settings.USER_OPTIONAL_FIELDS = DEFAULTS["USER_OPTIONAL_FIELDS"]

    def test_user_can_signup_with_the_same_email(self) -> None:
        response = self.client.post(
            "/api/v1/auth/users/",
            {
                "username": "test1",
                "email": self.email,
                "password": "testpass",
            },
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data["email"], self.email)
        self.assertEqual(response.data["username"], "test1")

        # Validation allows the same email to be used again
        # But we will get an IntegrityError from the database
        self.assertRaises(
            IntegrityError,
            lambda: self.client.post(
                "/api/v1/auth/users/",
                {
                    "username": "test2",
                    "email": self.email,
                    "password": "testpass",
                },
            ),
        )

    def test_user_can_signup_with_the_same_phone_number(self) -> None:
        response = self.client.post(
            "/api/v1/auth/users/",
            {
                "username": "test1",
                "phone_number": self.phone_number,
                "password": "testpass",
            },
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data["phone_number"], self.phone_number)
        self.assertEqual(response.data["username"], "test1")

        # Validation allows the same phone number to be used again
        # But we will get an IntegrityError from the database
        self.assertRaises(
            IntegrityError,
            lambda: self.client.post(
                "/api/v1/auth/users/",
                {
                    "username": "test2",
                    "phone_number": self.phone_number,
                    "password": "testpass",
                },
            ),
        )


class OtpViewSetAPITest(APITestCase):
    def setUp(self) -> None:
        self.client = APIClient()
        self.email = "test@te.st"

    def test_user_can_request_otp_with_registration(self) -> None:
        response = self.client.post(
            "/api/v1/auth/otp/",
            {
                "email": self.email,
            },
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        user = User.objects.get(email=self.email)
        device = EmailDevice.objects.get(user=user, name=self.email)
        self.assertTrue(device.confirmed)
        self.assertTrue(device.verify_token(device.token))


class OtpViewSetWithDisabledAnonOtpAPITest(APITestCase):
    def setUp(self) -> None:
        self.client = APIClient()
        self.email = "test@te.st"
        api_settings.OTP_SEND_UNAUTHORIZED_USER = False

    def tearDown(self) -> None:
        api_settings.OTP_SEND_UNAUTHORIZED_USER = True

    def test_unauthorized_user_cannot_request_otp(self) -> None:
        user = User.objects.create_user(
            username="testuser", password="testpass", email=self.email
        )
        EmailDevice.objects.create(
            user=user, name=self.email, confirmed=True, email=self.email
        )
        response = self.client.post(
            "/api/v1/auth/otp/",
            {
                "email": self.email,
            },
        )
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertEqual(response.data["errors"][0]["code"], "unauthorized_otp_request")


class OtpViewSetWithDisabledOtpAutoCreateAPITest(APITestCase):
    def setUp(self) -> None:
        self.client = APIClient()
        self.email = "test@te.st"
        api_settings.OTP_AUTO_CREATE_ACCOUNT = False

    def tearDown(self) -> None:
        api_settings.OTP_AUTO_CREATE_ACCOUNT = True

    def test_user_cannot_request_otp_without_registration(self) -> None:
        response = self.client.post(
            "/api/v1/auth/otp/",
            {
                "email": self.email,
            },
        )
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertEqual(
            response.data["errors"][0]["code"], UserDoesNotExistError.default_code
        )


class TokenViewSetAPITest(APITestCase):
    def setUp(self) -> None:
        self.client = APIClient()
        self.user = User.objects.create_user(
            username="testuser", password="testpass", email="test@te.st"
        )
        self.device = EmailDevice.objects.create(
            user=self.user, name=self.user.email, confirmed=True, email=self.user.email
        )

    def test_obtain_token_by_email_and_otp(self) -> None:
        self.device.generate_challenge()
        response = self.client.post(
            "/api/v1/auth/token/",
            {
                "email": self.user.email,
                "otp": self.device.token,
            },
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertNotEqual(response.data.get("token", ""), "")

    def test_obtain_token_by_username_and_password(self) -> None:
        response = self.client.post(
            "/api/v1/auth/token/",
            {
                "username": self.user.username,
                "password": "testpass",
            },
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertNotEqual(response.data.get("token", ""), "")


class TokenViewSet2FAAPITest(APITestCase):
    def setUp(self) -> None:
        self.client = APIClient()
        self.user = User.objects.create_user(
            username="testuser",
            password="testpass",
            email="test@te.st",
        )
        User2FA.objects.create(user=self.user, is_required=True)
        self.device = EmailDevice.objects.create(
            user=self.user, name=self.user.email, confirmed=True, email=self.user.email
        )

    def test_user_with_2fa_cannot_authorize_without_otp(self) -> None:
        response = self.client.post(
            "/api/v1/auth/token/",
            {
                "username": self.user.username,
                "password": "testpass",
            },
        )
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertEqual(response.data["errors"][0]["code"], "2fa_required")
        self.assertIn("devices", response.data["errors"][0]["extra_data"])
        devices = response.data["errors"][0]["extra_data"]["devices"]
        self.assertEqual(len(devices), 1)
        self.assertEqual(devices[0]["name"], self.device.name)
        self.assertEqual(devices[0]["type"], "email")

    def test_user_with_2fa_can_authorize_with_otp(self) -> None:
        self.device.generate_challenge()
        response = self.client.post(
            "/api/v1/auth/token/",
            {
                "username": self.user.username,
                "password": "testpass",
                "otp": self.device.token,
            },
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertNotEqual(response.data.get("token", ""), "")


class SocialTokenViewSetAPITest(APITestCase):
    def setUp(self) -> None:
        self.client = APIClient()
        self.email = "test@te.st"
        self.first_name = "Test"
        self.last_name = "User"
        httpretty.enable(verbose=True, allow_net_connect=False)
        httpretty.register_uri(
            httpretty.GET,
            "https://www.googleapis.com/oauth2/v3/userinfo",
            body=json.dumps(
                {
                    "email": self.email,
                    "name": f"{self.first_name} {self.last_name}",
                }
            ),
        )

    def tearDown(self) -> None:
        httpretty.disable()
        httpretty.reset()
        super().tearDown()

    def test_obtain_social_token_by_google_oauth2(self) -> None:
        User.objects.create_user(
            username="testuser",
            password="testpass",
            email=self.email,
        )

        response = self.client.post(
            "/api/v1/auth/social/",
            {
                "provider": "google-oauth2",
                "access_token": "test",
            },
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertNotEqual(response.data.get("token", ""), "")

    def test_social_login_creates_new_user(self) -> None:
        response = self.client.post(
            "/api/v1/auth/social/",
            {
                "provider": "google-oauth2",
                "access_token": "test",
            },
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertNotEqual(response.data.get("token", ""), "")
        users = list(User.objects.all())
        self.assertEqual(len(users), 1)
        user = users[0]
        self.assertEqual(user.email, self.email)  # type: ignore
        self.assertEqual(user.first_name, self.first_name)
        self.assertEqual(user.last_name, self.last_name)

    def test_social_login_fails_if_2fa_enabled(self) -> None:
        user = User.objects.create_user(
            username="testuser",
            password="testpass",
            email=self.email,
        )
        User2FA.objects.create(user=user, is_required=True)
        response = self.client.post(
            "/api/v1/auth/social/",
            {
                "provider": "google-oauth2",
                "access_token": "test",
            },
        )
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertEqual(response.data["errors"][0]["code"], "2fa_required")
        self.assertIn("devices", response.data["errors"][0]["extra_data"])

    def test_obtain_social_token_with_otp_for_2fa_user(self) -> None:
        user = User.objects.create_user(
            username="testuser",
            password="testpass",
            email=self.email,
            phone_number="+31612345678",
        )
        User2FA.objects.create(user=user, is_required=True)
        device = TwilioSMSDevice.objects.create(
            user=user, name=user.phone_number, confirmed=True, number=user.phone_number
        )
        device.generate_challenge()

        response = self.client.post(
            "/api/v1/auth/social/",
            {
                "provider": "google-oauth2",
                "access_token": "test",
                "otp": device.token,
            },
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertNotEqual(response.data.get("token", ""), "")


class SocialTokenViewSetWithoutNameAPITest(APITestCase):
    def setUp(self) -> None:
        self.client = APIClient()
        self.email = "test@te.st"
        self.first_name = "Test"
        self.last_name = "User"
        httpretty.enable(verbose=True, allow_net_connect=False)
        httpretty.register_uri(
            httpretty.GET,
            "https://www.googleapis.com/oauth2/v3/userinfo",
            body=json.dumps(
                {
                    "email": self.email,
                }
            ),
        )

    def tearDown(self) -> None:
        httpretty.disable()
        httpretty.reset()
        super().tearDown()

    def test_social_login_accepts_first_last_names_from_body(self) -> None:
        response = self.client.post(
            "/api/v1/auth/social/",
            {
                "provider": "google-oauth2",
                "access_token": "test",
                "first_name": self.first_name,
                "last_name": self.last_name,
            },
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertNotEqual(response.data.get("token", ""), "")
        users = list(User.objects.all())
        self.assertEqual(len(users), 1)
        user = users[0]
        self.assertEqual(user.email, self.email)  # type: ignore
        self.assertEqual(user.first_name, self.first_name)
        self.assertEqual(user.last_name, self.last_name)


class DisabledSignupAPITest(APITestCase):
    def setUp(self) -> None:
        self.client = APIClient()
        api_settings.SIGNUP_ALLOWED = False

    def tearDown(self) -> None:
        api_settings.SIGNUP_ALLOWED = True

    def test_signup_not_allowed(self) -> None:
        response = self.client.post(
            "/api/v1/auth/users/",
            {
                "password": "testpass",
                "email": "test@te.st",
            },
        )
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertEqual(response.data["errors"][0]["code"], "not_authenticated")


class DisabledInviteAPITest(APITestCase):
    def setUp(self) -> None:
        self.client = APIClient()
        self.user = User.objects.create_user(
            username="testuser",
            password="testpass",
        )
        self.client.force_authenticate(self.user)
        api_settings.INVITE_ALLOWED = False

    def tearDown(self) -> None:
        api_settings.INVITE_ALLOWED = True

    def test_invite_not_allowed(self) -> None:
        response = self.client.post(
            "/api/v1/auth/users/",
            {
                "password": "testpass",
                "email": "test@te.st",
            },
        )
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(response.data["errors"][0]["code"], "permission_denied")


class User2FAAPITest(APITestCase):
    def setUp(self) -> None:
        self.client = APIClient()
        self.user = User.objects.create_user(
            username="testuser",
            password="testpass",
        )
        self.client.force_authenticate(self.user)

    def test_user_2fa_retrieve(self) -> None:
        response = self.client.get(
            "/api/v1/auth/users/0/two-fa/",
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertFalse(response.data["is_required"])

    def test_user_2fa_update(self) -> None:
        response = self.client.patch(
            "/api/v1/auth/users/0/two-fa/",
            {
                "is_required": True,
            },
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data["is_required"])


class InactiveUserAPITest(APITestCase):
    def setUp(self) -> None:
        # Create a test user and set up any other objects you need
        self.email = "test@te.st"
        self.user = User.objects.create_user(
            username="testuser", password="testpass", is_active=False, email=self.email
        )
        self.client = APIClient()

    def test_inactive_user_request_otp(self) -> None:
        email_device = EmailDevice.objects.create(
            user=self.user,
            name=self.email,
            email=self.email,
            confirmed=True,
        )

        response = self.client.post(
            "/api/v1/auth/otp/",
            {
                "email": email_device.email,
            },
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.json()["errors"][0]["code"], "user_inactive")


def test_create_superuser() -> None:
    User.objects.create_superuser(
        username="testuser",
        password="testpass",
    )


class DeferredIdentityUpdateAPITest(APITestCase):
    """Test DEFER_IDENTITY_UPDATE setting that defers email/phone assignment until OTP confirmation"""

    def setUp(self) -> None:
        self.client = APIClient()
        self.email = "test@te.st"
        self.phone_number = "+31612345678"
        self.password = "testpass"
        # Configure username-only identity with deferred updates
        api_settings.USER_IDENTITY_FIELDS = {
            "username": "rest_framework.serializers.CharField",
        }
        api_settings.USER_OPTIONAL_FIELDS = {
            "first_name": "rest_framework.serializers.CharField",
            "last_name": "rest_framework.serializers.CharField",
            "password": "rest_framework.serializers.CharField",
            "email": "rest_framework.serializers.CharField",
            "phone_number": "phonenumber_field.serializerfields.PhoneNumberField",
        }
        api_settings.DEFER_IDENTITY_UPDATE = True
        api_settings.OTP_IDENTITY_UPDATE_FIELD = True

    def tearDown(self) -> None:
        api_settings.USER_IDENTITY_FIELDS = DEFAULTS["USER_IDENTITY_FIELDS"]
        api_settings.USER_OPTIONAL_FIELDS = DEFAULTS["USER_OPTIONAL_FIELDS"]
        api_settings.DEFER_IDENTITY_UPDATE = DEFAULTS["DEFER_IDENTITY_UPDATE"]

    def test_user_created_without_email_when_deferred(self) -> None:
        """Email should NOT be saved to user model during registration"""
        response = self.client.post(
            "/api/v1/auth/users/",
            {
                "username": "john",
                "email": self.email,
                "password": self.password,
            },
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data["username"], "john")
        # Email should NOT be in the response or user model
        self.assertIsNone(response.data.get("email"))

        user = User.objects.get(username="john")
        self.assertFalse(user.email)  # Email is None or blank

    def test_email_device_created_with_deferred_email(self) -> None:
        """EmailDevice should be created with the email even though user.email is blank"""
        response = self.client.post(
            "/api/v1/auth/users/",
            {
                "username": "john",
                "email": self.email,
                "password": self.password,
            },
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        user = User.objects.get(username="john")
        self.assertFalse(user.email)  # User email is None or blank

        # But device should exist with the email
        device = EmailDevice.objects.get(user=user)
        self.assertEqual(device.email, self.email)
        self.assertEqual(device.name, self.email)
        self.assertFalse(device.confirmed)

    def test_email_updated_after_otp_confirmation(self) -> None:
        """User's email should be updated from device when OTP is confirmed"""
        # Create user with deferred email
        self.client.post(
            "/api/v1/auth/users/",
            {
                "username": "john",
                "email": self.email,
                "password": self.password,
            },
        )

        user = User.objects.get(username="john")
        self.assertFalse(user.email)  # Email is None or blank initially

        device = EmailDevice.objects.get(user=user)
        self.assertFalse(device.confirmed)

        # Authenticate and confirm device
        client = APIClient()
        client.force_authenticate(user=user)

        # Generate OTP token directly (simulating email being sent)
        device.generate_challenge()
        device.refresh_from_db()
        self.assertIsNotNone(device.token)

        # Confirm device with OTP
        response = client.post(
            f"/api/v1/auth/otp-devices/{device.pk}/confirm/?type=email",
            {"otp": device.token},
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Now user's email should be updated!
        user.refresh_from_db()
        self.assertEqual(user.email, self.email)
        device.refresh_from_db()
        self.assertTrue(device.confirmed)

    def test_phone_number_deferred_and_updated(self) -> None:
        """Phone number should be deferred and updated on confirmation"""
        # Create user with deferred phone
        response = self.client.post(
            "/api/v1/auth/users/",
            {
                "username": "john",
                "phone_number": self.phone_number,
                "password": self.password,
            },
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        user = User.objects.get(username="john")
        self.assertIsNone(user.phone_number)  # Phone is None!

        # Device should exist with phone number
        device = TwilioSMSDevice.objects.get(user=user)
        self.assertEqual(str(device.number), self.phone_number)
        self.assertFalse(device.confirmed)

        # Authenticate and confirm device
        client = APIClient()
        client.force_authenticate(user=user)

        # Generate OTP token directly (simulating SMS being sent)
        device.generate_challenge()
        device.refresh_from_db()
        self.assertIsNotNone(device.token)

        # Confirm device
        response = client.post(
            f"/api/v1/auth/otp-devices/{device.pk}/confirm/?type=sms",
            {"otp": device.token},
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Phone should now be updated!
        user.refresh_from_db()
        self.assertEqual(str(user.phone_number), self.phone_number)

    def test_both_email_and_phone_deferred(self) -> None:
        """Both email and phone should be deferred when provided together"""
        response = self.client.post(
            "/api/v1/auth/users/",
            {
                "username": "john",
                "email": self.email,
                "phone_number": self.phone_number,
                "password": self.password,
            },
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        user = User.objects.get(username="john")
        self.assertFalse(user.email)  # Email is None or blank
        self.assertIsNone(user.phone_number)

        # Both devices should exist
        email_device = EmailDevice.objects.get(user=user)
        self.assertEqual(email_device.email, self.email)
        self.assertFalse(email_device.confirmed)

        phone_device = TwilioSMSDevice.objects.get(user=user)
        self.assertEqual(str(phone_device.number), self.phone_number)
        self.assertFalse(phone_device.confirmed)

    def test_multiple_users_can_have_same_unconfirmed_email(self) -> None:
        """Multiple users should be able to register with same email when it's not an identity field"""
        # User 1
        response = self.client.post(
            "/api/v1/auth/users/",
            {
                "username": "john",
                "email": self.email,
                "password": self.password,
            },
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        # User 2 with SAME email - should succeed!
        response = self.client.post(
            "/api/v1/auth/users/",
            {
                "username": "jane",
                "email": self.email,  # Same email!
                "password": self.password,
            },
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        # Both users should exist with blank emails
        user1 = User.objects.get(username="john")
        user2 = User.objects.get(username="jane")
        self.assertFalse(user1.email)  # Email is None or blank
        self.assertFalse(user2.email)  # Email is None or blank

        # Both should have unconfirmed devices with same email
        device1 = EmailDevice.objects.get(user=user1)
        device2 = EmailDevice.objects.get(user=user2)
        self.assertEqual(device1.email, self.email)
        self.assertEqual(device2.email, self.email)


class AutoSendIdentityVerificationOTPAPITest(APITestCase):
    """Test AUTO_SEND_IDENTITY_VERIFICATION_OTP setting that auto-sends OTPs on registration"""

    def setUp(self) -> None:
        self.client = APIClient()
        self.email = "test@te.st"
        self.phone_number = "+31612345678"
        self.password = "testpass"
        api_settings.AUTO_SEND_IDENTITY_VERIFICATION_OTP = True

    def tearDown(self) -> None:
        api_settings.AUTO_SEND_IDENTITY_VERIFICATION_OTP = DEFAULTS[
            "AUTO_SEND_IDENTITY_VERIFICATION_OTP"
        ]

    def test_otp_sent_to_email_on_registration(self) -> None:
        """OTP should be automatically sent to email when user registers"""
        response = self.client.post(
            "/api/v1/auth/users/",
            {
                "email": self.email,
                "password": self.password,
            },
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        user = User.objects.get(email=self.email)
        device = EmailDevice.objects.get(user=user, email=self.email)

        # Device should be created but not confirmed
        self.assertFalse(device.confirmed)
        # OTP token should have been generated
        self.assertIsNotNone(device.token)

    def test_otp_sent_to_phone_on_registration(self) -> None:
        """OTP should be automatically sent to phone when user registers"""
        response = self.client.post(
            "/api/v1/auth/users/",
            {
                "phone_number": self.phone_number,
                "password": self.password,
            },
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        user = User.objects.get(phone_number=self.phone_number)
        device = TwilioSMSDevice.objects.get(user=user, number=self.phone_number)

        # Device should be created but not confirmed
        self.assertFalse(device.confirmed)
        # OTP token should have been generated
        self.assertIsNotNone(device.token)

    def test_otp_sent_to_both_email_and_phone(self) -> None:
        """OTPs should be sent to both email and phone when both provided"""
        response = self.client.post(
            "/api/v1/auth/users/",
            {
                "email": self.email,
                "phone_number": self.phone_number,
                "password": self.password,
            },
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        user = User.objects.get(email=self.email)

        email_device = EmailDevice.objects.get(user=user, email=self.email)
        phone_device = TwilioSMSDevice.objects.get(user=user, number=self.phone_number)

        # Both devices should have OTP tokens
        self.assertIsNotNone(email_device.token)
        self.assertIsNotNone(phone_device.token)
        self.assertFalse(email_device.confirmed)
        self.assertFalse(phone_device.confirmed)

    def test_user_can_confirm_with_auto_sent_otp(self) -> None:
        """User should be able to confirm their email with the auto-sent OTP"""
        response = self.client.post(
            "/api/v1/auth/users/",
            {
                "email": self.email,
                "password": self.password,
            },
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        user = User.objects.get(email=self.email)
        device = EmailDevice.objects.get(user=user, email=self.email)

        # OTP was auto-sent
        self.assertIsNotNone(device.token)
        otp_token = device.token

        # User authenticates and confirms device
        client = APIClient()
        client.force_authenticate(user=user)

        response = client.post(
            f"/api/v1/auth/otp-devices/{device.pk}/confirm/?type=email",
            {"otp": otp_token},
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        device.refresh_from_db()
        self.assertTrue(device.confirmed)

    def test_no_otp_sent_when_setting_disabled(self) -> None:
        """OTP should NOT be sent when AUTO_SEND_IDENTITY_VERIFICATION_OTP is False"""
        api_settings.AUTO_SEND_IDENTITY_VERIFICATION_OTP = False

        response = self.client.post(
            "/api/v1/auth/users/",
            {
                "email": self.email,
                "password": self.password,
            },
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        user = User.objects.get(email=self.email)
        device = EmailDevice.objects.get(user=user, email=self.email)

        # Device created but no OTP sent
        self.assertFalse(device.confirmed)
        self.assertIsNone(device.token)


class AutoSendWithDeferredIdentityAPITest(APITestCase):
    """Test AUTO_SEND_IDENTITY_VERIFICATION_OTP with DEFER_IDENTITY_UPDATE enabled"""

    def setUp(self) -> None:
        self.client = APIClient()
        self.email = "test@te.st"
        self.phone_number = "+31612345678"
        self.password = "testpass"

        # Configure username-only identity with both features enabled
        api_settings.USER_IDENTITY_FIELDS = {
            "username": "rest_framework.serializers.CharField",
        }
        api_settings.USER_OPTIONAL_FIELDS = {
            "email": "rest_framework.serializers.CharField",
            "phone_number": "phonenumber_field.serializerfields.PhoneNumberField",
            "password": "rest_framework.serializers.CharField",
        }
        api_settings.DEFER_IDENTITY_UPDATE = True
        api_settings.AUTO_SEND_IDENTITY_VERIFICATION_OTP = True
        api_settings.OTP_IDENTITY_UPDATE_FIELD = True

    def tearDown(self) -> None:
        api_settings.USER_IDENTITY_FIELDS = DEFAULTS["USER_IDENTITY_FIELDS"]
        api_settings.USER_OPTIONAL_FIELDS = DEFAULTS["USER_OPTIONAL_FIELDS"]
        api_settings.DEFER_IDENTITY_UPDATE = DEFAULTS["DEFER_IDENTITY_UPDATE"]
        api_settings.AUTO_SEND_IDENTITY_VERIFICATION_OTP = DEFAULTS[
            "AUTO_SEND_IDENTITY_VERIFICATION_OTP"
        ]

    def test_deferred_email_receives_auto_otp(self) -> None:
        """Deferred email should still receive auto-sent OTP"""
        response = self.client.post(
            "/api/v1/auth/users/",
            {
                "username": "john",
                "email": self.email,
                "password": self.password,
            },
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        user = User.objects.get(username="john")
        self.assertFalse(user.email)  # Email is deferred (not on user model)

        device = EmailDevice.objects.get(user=user)
        self.assertEqual(device.email, self.email)
        self.assertFalse(device.confirmed)
        # OTP should have been auto-sent
        self.assertIsNotNone(device.token)

    def test_confirm_deferred_email_updates_user(self) -> None:
        """Confirming deferred email should update user's email field"""
        response = self.client.post(
            "/api/v1/auth/users/",
            {
                "username": "john",
                "email": self.email,
                "password": self.password,
            },
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        user = User.objects.get(username="john")
        device = EmailDevice.objects.get(user=user)
        otp_token = device.token

        # Confirm device with auto-sent OTP
        client = APIClient()
        client.force_authenticate(user=user)

        response = client.post(
            f"/api/v1/auth/otp-devices/{device.pk}/confirm/?type=email",
            {"otp": otp_token},
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # User's email should now be updated from the confirmed device
        user.refresh_from_db()
        self.assertEqual(user.email, self.email)
        device.refresh_from_db()
        self.assertTrue(device.confirmed)
