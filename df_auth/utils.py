from typing import Dict, List, Tuple, Type

from django.utils.module_loading import import_string
from django_otp.models import Device

from .settings import api_settings


def get_otp_device_models() -> Dict[str, Type[Device]]:
    return {
        type_: import_string(model_path)
        for type_, model_path in api_settings.OTP_DEVICE_MODELS.items()
    }


def get_otp_device_choices() -> List[Tuple[str, str]]:
    return [(type_, type_) for type_ in api_settings.OTP_DEVICE_MODELS]
