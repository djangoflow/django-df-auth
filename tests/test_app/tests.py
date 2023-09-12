import json

import httpretty
from django.db import IntegrityError
from django.urls import reverse
from django_otp.plugins.otp_email.models import EmailDevice
from django_otp.plugins.otp_totp.models import TOTPDevice
from otp_twilio.models import TwilioSMSDevice
from rest_framework import status
from rest_framework.test import APIClient, APITestCase

from df_auth.exceptions import UserDoesNotExistError
from df_auth.settings import DEFAULTS, api_settings
from tests.test_app.models import User


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
            reverse("df_api_drf:v1:auth:otp-device-list"),
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
            reverse("df_api_drf:v1:auth:otp-device-list"),
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

        # Check we will not return the key again
        response = self.client.get(reverse("df_api_drf:v1:auth:otp-device-list"))
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

        send_url = reverse("df_api_drf:v1:auth:otp-list")
        response = self.client.post(
            f"{send_url}",
            {
                "email": email_device.email,
            },
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        email_device.refresh_from_db()
        self.assertIsNotNone(email_device.token)

        confirm_url = reverse(
            "df_api_drf:v1:auth:otp-device-confirm", kwargs={"pk": email_device.pk}
        )
        response = self.client.post(
            f"{confirm_url}?type=email",
            {"otp": "wrong-token"},
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        email_device.refresh_from_db()
        self.assertFalse(email_device.confirmed)
        email_device.throttle_reset(commit=True)

        self.user.refresh_from_db()
        self.assertIsNone(self.user.email)
        response = self.client.post(
            f"{confirm_url}?type=email",
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

        response = self.client.get(reverse("df_api_drf:v1:auth:otp-device-list"))
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data["results"]), 1)
        self.assertEqual(response.data["results"][0]["name"], self.email)
        self.assertEqual(response.data["results"][0]["type"], "email")

        response = self.client.delete(
            reverse(
                "df_api_drf:v1:auth:otp-device-detail", kwargs={"pk": email_device.pk}
            )
            + "?type=email"
        )
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)

        response = self.client.get(reverse("df_api_drf:v1:auth:otp-device-list"))
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
        response = self.client.get(reverse("df_api_drf:v1:auth:otp-device-list"))
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
            reverse("df_api_drf:v1:auth:user-list"),
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
            reverse("df_api_drf:v1:auth:user-detail", kwargs={"pk": user.pk})
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
            reverse("df_api_drf:v1:auth:user-list"),
            {
                "phone_number": phone_2,
                "email": email_2,
            },
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data["phone_number"], phone_2)

        user_2 = User.objects.get(phone_number=phone_2)
        self.assertEqual(user_2.created_by, user_1)
        phone_device = TwilioSMSDevice.objects.get(user=user_2, name=phone_2)
        self.assertFalse(phone_device.confirmed)
        email_device = EmailDevice.objects.get(user=user_2, name=email_2)
        self.assertFalse(email_device.confirmed)

    def test_user_nl_phone_strips_zero(self) -> None:
        response = self.client.post(
            reverse("df_api_drf:v1:auth:user-list"),
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
            reverse("df_api_drf:v1:auth:user-detail", kwargs={"pk": user.pk}),
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
            reverse("df_api_drf:v1:auth:user-detail", kwargs={"pk": user.pk}),
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
            reverse("df_api_drf:v1:auth:user-detail", kwargs={"pk": user.pk}),
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
            reverse("df_api_drf:v1:auth:user-set-password", kwargs={"pk": user.pk}),
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
            reverse("df_api_drf:v1:auth:user-set-password", kwargs={"pk": user.pk}),
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
            reverse("df_api_drf:v1:auth:user-list"),
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
            reverse("df_api_drf:v1:auth:user-list"),
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
            reverse("df_api_drf:v1:auth:user-list"),
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
                reverse("df_api_drf:v1:auth:user-list"),
                {
                    "username": "test2",
                    "email": self.email,
                    "password": "testpass",
                },
            ),
        )

    def test_user_can_signup_with_the_same_phone_number(self) -> None:
        response = self.client.post(
            reverse("df_api_drf:v1:auth:user-list"),
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
                reverse("df_api_drf:v1:auth:user-list"),
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
            reverse("df_api_drf:v1:auth:otp-list"),
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
            reverse("df_api_drf:v1:auth:otp-list"),
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
            reverse("df_api_drf:v1:auth:otp-list"),
            {
                "email": self.email,
            },
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
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
            reverse("df_api_drf:v1:auth:token-list"),
            {
                "email": self.user.email,
                "otp": self.device.token,
            },
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertNotEqual(response.data.get("token", ""), "")

    def test_obtain_token_by_username_and_password(self) -> None:
        response = self.client.post(
            reverse("df_api_drf:v1:auth:token-list"),
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
            is_2fa_enabled=True,
        )
        self.device = EmailDevice.objects.create(
            user=self.user, name=self.user.email, confirmed=True, email=self.user.email
        )

    def test_user_with_2fa_cannot_authorize_without_otp(self) -> None:
        response = self.client.post(
            reverse("df_api_drf:v1:auth:token-list"),
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
            reverse("df_api_drf:v1:auth:token-list"),
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
            reverse("df_api_drf:v1:auth:social-list"),
            {
                "provider": "google-oauth2",
                "access_token": "test",
            },
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertNotEqual(response.data.get("token", ""), "")

    def test_social_login_creates_new_user(self) -> None:
        response = self.client.post(
            reverse("df_api_drf:v1:auth:social-list"),
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
        User.objects.create_user(
            username="testuser",
            password="testpass",
            email=self.email,
            is_2fa_enabled=True,
        )
        response = self.client.post(
            reverse("df_api_drf:v1:auth:social-list"),
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
            is_2fa_enabled=True,
        )
        device = TwilioSMSDevice.objects.create(
            user=user, name=user.phone_number, confirmed=True, number=user.phone_number
        )
        device.generate_challenge()

        response = self.client.post(
            reverse("df_api_drf:v1:auth:social-list"),
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
            reverse("df_api_drf:v1:auth:social-list"),
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
            reverse("df_api_drf:v1:auth:user-list"),
            {
                "password": "testpass",
                "email": "test@te.st",
            },
        )
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(response.data["errors"][0]["code"], "signup_not_allowed")
