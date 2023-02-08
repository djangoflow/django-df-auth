from django.contrib.auth import get_user_model

import pytest

User = get_user_model()

pytestmark = [pytest.mark.django_db]


def test_dummy():
    assert 1 == 1
