"""
Unit tests for the authentication serializers.

These tests validate the correct behavior of the following serializers:
    - TokenSerializer
    - TokenCreateSerializer
    - TokenObtainSerializer
    - FirstLastNameSerializerMixin
    - SocialTokenObtainSerializer

Each test case validates the correct behavior of one or more methods or attributes
of the corresponding serializer.

"""

from rest_framework import serializers
from df_auth.drf.serializers import (
    TokenSerializer,
    TokenCreateSerializer,
    TokenObtainSerializer,
    FirstLastNameSerializerMixin,
    SocialTokenObtainSerializer,
    AUTHENTICATION_BACKENDS
)
import unittest
from unittest.mock import patch, MagicMock
from .models import User
from rest_framework_simplejwt.settings import api_settings as simplejwt_settings
from rest_framework import exceptions
from rest_framework.exceptions import AuthenticationFailed


class TokenSerializerTestCase(unittest.TestCase):
    """Test case for the TokenSerializer."""

    def setUp(self):
        """Set up the test case by instantiating the TokenSerializer."""
        self.serializer = TokenSerializer()

    def test_token_field(self):
        """Test that the token field is present and read-only."""
        fields = self.serializer.get_fields()
        self.assertIn('token', fields)
        self.assertIsInstance(fields['token'], serializers.CharField)
        self.assertTrue(fields['token'].read_only)

    def test_token_class_attribute(self):
        """Test that the token_class attribute can be mocked."""
        with patch('df_auth.drf.serializers.TokenSerializer.token_class', 'mocked_token_class'):
            serializer = TokenSerializer()  # Create a new instance after the patch is applied
            self.assertEqual(serializer.token_class, 'mocked_token_class')

    def test_user_attribute(self):
        """Test that the user attribute is initially None."""
        self.assertIsNone(self.serializer.user)


class TokenCreateSerializerTestCase(unittest.TestCase):
    """Test case for the TokenCreateSerializer."""

    def setUp(self):
        """Set up the test case by instantiating the TokenCreateSerializer."""
        self.serializer = TokenCreateSerializer()

    def test_inheritance(self):
        """Test that the TokenCreateSerializer inherits from TokenSerializer."""
        self.assertIsInstance(self.serializer, TokenSerializer)

    def test_get_token(self):
        """Test that get_token method returns a valid token."""
        with patch.object(TokenCreateSerializer, 'token_class', MagicMock()) as mocked_token_class:
            mocked_token = MagicMock()
            mocked_token_class.for_user.return_value = mocked_token
            user = User()
            token = TokenCreateSerializer.get_token(user)
            self.assertEqual(token, mocked_token)
            mocked_token_class.for_user.assert_called_once_with(user)

    def test_validate_with_valid_authentication_rule(self):
        """Test that validate method returns a token with a valid authentication rule."""
        user = User()
        self.serializer.user = user

        with patch.object(simplejwt_settings, 'USER_AUTHENTICATION_RULE', return_value=True):
            with patch.object(TokenCreateSerializer, 'get_token', return_value='mocked_token'):
                with patch.object(simplejwt_settings, 'UPDATE_LAST_LOGIN', False):
                    attrs = self.serializer.validate({})
                    self.assertEqual(attrs, {'token': 'mocked_token'})

    def test_validate_with_invalid_authentication_rule(self):
        """Test that validate method raises an exception with an invalid authentication rule."""
        user = User()
        self.serializer.user = user

        with patch.object(simplejwt_settings, 'USER_AUTHENTICATION_RULE', return_value=False):
            with self.assertRaises(exceptions.AuthenticationFailed):
                self.serializer.validate({})


class TokenObtainSerializerTestCase(unittest.TestCase):
    """
    Test case for TokenObtainSerializer.
    """

    def setUp(self):
        """
        Initialize the TokenObtainSerializer.
        """
        self.created_users = set()
        self.serializer = TokenObtainSerializer()

    def test_missing_credentials(self):
        """
        Test that missing credentials raises AuthenticationFailed exception.
        """
        data = {}
        with self.assertRaises(AuthenticationFailed):
            self.serializer.validate(data)

    def test_invalid_credentials(self):
        """
        Test that invalid credentials raises AuthenticationFailed exception.
        """
        data = {'email': 'invalid', 'password': 'invalid'}
        with self.assertRaises(AuthenticationFailed):
            self.serializer.validate(data)

    @patch('df_auth.drf.serializers.authenticate')
    @patch('df_auth.drf.serializers.TokenCreateSerializer.get_token')
    def test_valid_credentials(self, mocked_get_token, mocked_authenticate):
        """
        Test that valid credentials returns validated data with a token.
        """
        user = User.objects.create_user(
            email='testuser@example.com',
            password='testpass'
        )
        self.created_users.add(user)
        mocked_authenticate.return_value = user
        mocked_token = MagicMock()
        mocked_get_token.return_value = mocked_token

        data = {'email': 'testuser@example.com', 'password': 'testpass'}
        validated_data = self.serializer.validate(data)

        self.assertIn('token', validated_data)
        self.assertEqual(validated_data['token'], str(mocked_token))
        mocked_authenticate.assert_called_once_with(email='testuser@example.com', password='testpass')
        mocked_get_token.assert_called_once_with(user)



    @patch('df_auth.drf.serializers.authenticate')
    @patch('df_auth.drf.serializers.TokenCreateSerializer.get_token')
    def test_additional_fields(self, mocked_get_token, mocked_authenticate):
        """
        Test that additional fields are not included in the validated data.
        """
        user2 = User.objects.create_user(
            email='testuser2@example.com',
            password='testpass'
        )
        self.created_users.add(user2)
        mocked_authenticate.return_value = user2
        mocked_token = MagicMock()
        mocked_get_token.return_value = mocked_token

        data = {'email': 'testuser2@example.com', 'password': 'testpass', 'additional_field': None}
        validated_data = self.serializer.validate(data)

        self.assertNotIn('additional_field', validated_data)


    def tearDown(self):
        if self.created_users:
            # Delete only the users that were created during the test
            User.objects.filter(id__in=[user.id for user in self.created_users]).delete()


class TestFirstLastNameSerializer(FirstLastNameSerializerMixin):
    """
    Serializer to test FirstLastNameSerializerMixin.
    """
    pass


class FirstLastNameSerializerTestCase(unittest.TestCase):
    """
    Test case for FirstLastNameSerializer.
    """

    def setUp(self):
        """
        Initialize the FirstLastNameSerializer.
        """
        self.serializer = TestFirstLastNameSerializer()

    def test_first_last_name_fields(self):
        """
        Test that the FirstLastNameSerializer has the correct fields.
        """
        serializer = TestFirstLastNameSerializer()
        fields = serializer.get_fields()
        self.assertIn('first_name', fields)
        self.assertEqual(serializers.CharField, fields['first_name'].__class__)
        self.assertEqual(False, fields['first_name'].required)
        self.assertIn('last_name', fields)
        self.assertEqual(serializers.CharField, fields['last_name'].__class__)
        self.assertEqual(False, fields['last_name'].required)


class TestSocialTokenObtainSerializer(SocialTokenObtainSerializer):
    """
    Serializer to test SocialTokenObtainSerializer.
    """
    pass



class SocialTokenObtainSerializerTestCase(unittest.TestCase):
    """
    Test case for SocialTokenObtainSerializer.
    """
    def setUp(self):
        """
        Initialize the SocialTokenObtainSerializer.
        """
        self.serializer = TestSocialTokenObtainSerializer()

    def test_get_fields(self):
        """
        Test the fields returned by the SocialTokenObtainSerializer.
        """
        serializer = TestSocialTokenObtainSerializer()

        fields = serializer.get_fields()

        # Test first_name field
        self.assertIn('first_name', fields)
        self.assertEqual(serializers.CharField, fields['first_name'].__class__)
        self.assertEqual(False, fields['first_name'].required)

        # Test last_name field
        self.assertIn('last_name', fields)
        self.assertEqual(serializers.CharField, fields['last_name'].__class__)
        self.assertEqual(False, fields['last_name'].required)

        # Test access_token field
        self.assertIn('access_token', fields)
        self.assertEqual(serializers.CharField, fields['access_token'].__class__)
        self.assertEqual(True, fields['access_token'].write_only)

        # Test provider field
        self.assertIn('provider', fields)
        self.assertEqual(serializers.ChoiceField, fields['provider'].__class__)
        self.assertEqual(
            [(backend.name, backend.name) for backend in AUTHENTICATION_BACKENDS if hasattr(backend, "name")],
            list(fields['provider'].choices.items())
        )

        # Test response field
        self.assertIn('response', fields)
        self.assertEqual(serializers.JSONField, fields['response'].__class__)
        self.assertEqual(True, fields['response'].read_only)

    def test_validate(self):
        user = MagicMock(spec=User)
        attrs = {
            'access_token': 'test_access_token',
            'provider': 'test_provider',
            'first_name': 'Test',
            'last_name': 'User',
        }

        with patch('df_auth.drf.serializers.load_backend') as mock_load_backend, \
                patch('df_auth.drf.serializers.DRFStrategy') as mock_drf_strategy, \
                patch('df_auth.drf.serializers.DjangoStorage') as mock_django_storage:
            mock_load_backend.return_value.do_auth.return_value = user
            context = {'request': MagicMock()}
            serializer = TestSocialTokenObtainSerializer(context=context)
            validated_data = serializer.validate(attrs)
            self.assertIn('token', validated_data)


if __name__ == '__main__':
    unittest.main()