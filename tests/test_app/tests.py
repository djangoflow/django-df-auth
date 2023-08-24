from django.urls import reverse
from django_otp.plugins.otp_email.models import EmailDevice
from django_otp.plugins.otp_totp.models import TOTPDevice
from otp_twilio.models import TwilioSMSDevice
from rest_framework import status
from rest_framework.test import APIClient, APITestCase

from tests.test_app.models import User


class OtpDeviceAPITest(APITestCase):
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
            confirmed=False,
        )
        self.assertIsNone(email_device.token)

        send_url = reverse(
            "df_api_drf:v1:auth:otp-device-send-otp", kwargs={"pk": email_device.pk}
        )
        response = self.client.post(f"{send_url}?type=email")
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

        response = self.client.post(
            f"{confirm_url}?type=email",
            {"otp": email_device.token},
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        email_device.refresh_from_db()
        self.assertTrue(email_device.confirmed)

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
