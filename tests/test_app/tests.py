from django.urls import reverse
from django_otp.plugins.otp_email.models import EmailDevice
from django_otp.plugins.otp_totp.models import TOTPDevice
from otp_twilio.models import TwilioSMSDevice
from rest_framework import status
from rest_framework.test import APIClient, APITestCase

from df_auth.exceptions import UserDoesNotExistError
from df_auth.settings import api_settings
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

    def test_totp_device_has_key(self) -> None:
        TOTPDevice.objects.create(
            user=self.user,
            name="default",
        )
        response = self.client.get(reverse("df_api_drf:v1:auth:otp-device-list"))
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data["results"]), 1)
        self.assertIsNotNone(response.data["results"][0]["key"])


class UserViewSetAPITest(APITestCase):
    def setUp(self) -> None:
        # Create a test user and set up any other objects you need
        self.client = APIClient()
        self.email = "test@te.st"
        self.phone_number = "+1234567890"
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

        user = User.objects.get(email=self.email)
        self.assertTrue(user.check_password(self.password))
        self.assertEqual(user.username, self.email)

        device = EmailDevice.objects.get(user=user, name=self.email)
        self.assertFalse(device.confirmed)

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
        self.assertEqual(user_2.invited_by, user_1)
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
        api_settings.SEND_OTP_UNAUTHORIZED_USER = False

    def tearDown(self) -> None:
        api_settings.SEND_OTP_UNAUTHORIZED_USER = True

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
        api_settings.OTP_AUTO_CREATE_ACCOUNT = False

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
