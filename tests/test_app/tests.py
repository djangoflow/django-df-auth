from django.contrib.auth import get_user_model
from django.test import RequestFactory
from rest_framework_simplejwt.tokens import AccessToken
import pytest
from df_auth.drf.serializers import TokenCreateSerializer
from df_auth.drf.serializers import TokenObtainSerializer
from df_auth.drf.serializers import OTPObtainSerializer
from df_auth.drf.serializers import SignupSerializer
from df_auth.drf.serializers import InviteSerializer
from rest_framework_simplejwt.settings import api_settings as simplejwt_settings

User = get_user_model()

pytestmark = [pytest.mark.django_db]


def test_dummy():
    assert 1 == 1


def test_token_create_serializer_get_token():
    user = User.objects.create_user(email='test@test.com', password='12345')
    serializer = TokenCreateSerializer(user)
    token = serializer.get_token(user)
    assert isinstance(token, AccessToken)
    assert token['token_type'] == 'access'
    assert token['user_id'] == user.id
    assert 'exp' in token
    assert 'jti' in token


def test_token_create_serializer_validate():
    user = User.objects.create_user(email='test@test.com', password='12345')
    payload = {'email':'test@test.com','password':'12345'}
    serializer = TokenCreateSerializer(data=payload)
    serializer.user=user
    assert serializer.is_valid(raise_exception=True) is True

def test_token_obtain_serializer_get_fields():
    serializer = TokenObtainSerializer()
    expected_fields = ['email', 'phone_number','password','otp','token']
    fields = serializer.get_fields()
    assert len(fields.keys()) == len(expected_fields)
    assert all([field in fields.keys() for field in expected_fields])


def test_token_obtain_serializer_validate():
    user = User.objects.create_user(email='test@test.com', password='12345')
    payload = {'email':'test@test.com','password':'12345'}
    serializer = TokenObtainSerializer(data=payload)
    serializer.user=user
    assert serializer.is_valid(raise_exception=True) is True


def test_otp_obtain_serializer_get_fields():
    serializer =  OTPObtainSerializer()
    expected_fields = ['email', 'phone_number','password','otp']
    fields = serializer.get_fields()
    assert len(fields.keys())== len(expected_fields)
    assert all([field in fields.keys() for field in expected_fields])


def test_otp_obtain_serializer_validate():
    factory = RequestFactory()
    user = User.objects.create_user(email='test@test.com', password='12345')
    payload = {'email':'test@test.com','password':'12345'}
    request = factory.get('/')
    request.user = user
    serializer = OTPObtainSerializer(data=payload, context={'request': request})
    serializer.user=user
    assert serializer.is_valid(raise_exception=True) is True


def test_sign_up_serializer_validate():
    factory = RequestFactory()
    payload = {'email':'test@test.com','password':'12345','first_name':'Test','last_name':'Tester'}
    request = factory.get('/')
    serializer = SignupSerializer(data=payload, context={'request': request})
    assert serializer.is_valid(raise_exception=True) is True


def test_invite_serializer_validate():
    factory = RequestFactory()
    user = User.objects.create_user(email='test@test.com', password='12345')
    payload = {'email':'test@test.com'}
    request = factory.get('/')
    request.user = user
    serializer = InviteSerializer(data=payload, context={'request': request})
    serializer.user=user
    assert serializer.is_valid(raise_exception=True) is True
