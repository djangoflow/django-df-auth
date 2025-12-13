# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

`django-df-auth` is an opinionated Django REST authentication module providing JWT-based authentication with OTP/2FA support and social login integration. It's a glue package combining djangorestframework, simplejwt, python-social-auth, django-otp, and twilio for a complete authentication solution.

## Development Commands

### Testing

```bash
# Run all tests
pytest

# Run specific test file
pytest tests/test_app/tests.py

# Run specific test class
pytest tests/test_app/tests.py::OtpDeviceViewSetAPITest

# Run specific test method
pytest tests/test_app/tests.py::OtpDeviceViewSetAPITest::test_create_email_device

# Run with verbose output
pytest -v

# Run with output (show print statements)
pytest -s
```

### Code Quality

```bash
# Format code with black
black .

# Lint with ruff (auto-fix)
ruff check --fix .

# Type checking with mypy
mypy df_auth

# Run pre-commit hooks manually
pre-commit run --all-files
```

### Development Server

```bash
# Run Django development server (for testing)
python manage.py runserver

# Create migrations (if extending models)
python manage.py makemigrations

# Apply migrations
python manage.py migrate

# Create superuser
python manage.py createsuperuser
```

### Building & Distribution

```bash
# Build package
python -m build

# Install in editable mode for development
pip install -e .

# Install with test dependencies
pip install -e ".[test]"
```

## Architecture

### Core Authentication Flow

The package provides multiple authentication backends that work together:

1. **TestEmailBackend** (`df_auth/backends.py:21`) - Test-only backend for automated testing
2. **EmailOTPBackend** (`df_auth/backends.py:127`) - OTP via email with magic link support
3. **TwilioSMSOTPBackend** (`df_auth/backends.py:148`) - OTP via SMS using Twilio
4. **ModelBackend** - Standard Django username/password authentication
5. **Social Auth Backends** - Google OAuth2, Facebook, Apple ID, Twitter

All backends are configured in `AUTHENTICATION_BACKENDS` and are tried sequentially during authentication.

### Key Components

**Authentication Backends** (`df_auth/backends.py`)
- `BaseOTPBackend` - Abstract base for OTP authentication with `generate_challenge()` and `authenticate()` methods
- OTP backends implement identity field mapping (email -> email, phone_number -> number)
- Supports auto-account creation via `OTP_AUTO_CREATE_ACCOUNT` setting

**Serializers** (`df_auth/drf/serializers.py`)
- `TokenObtainSerializer` (line 81) - Handles multiple auth methods (password, OTP, combinations)
- `OTPObtainSerializer` (line 148) - Generates and sends OTP challenges
- `SocialTokenObtainSerializer` (line 186) - Social login with optional 2FA
- `UserIdentitySerializer` (line 324) - User registration/update with flexible identity fields
- All serializers use dynamic field building based on `DF_AUTH` settings

**ViewSets** (`df_auth/drf/viewsets.py`)
- `TokenViewSet` - Token obtain/refresh/verify/blacklist endpoints
- `OTPViewSet` - OTP request endpoint
- `OtpDeviceViewSet` - Manage user's OTP devices (create, list, confirm, delete)
- `UserViewSet` - User registration, profile management, password changes, 2FA settings
- `SocialTokenViewSet` - Social login and account connection

**Models** (`df_auth/models.py`)
- `User2FA` - Per-user 2FA requirement flag
- `UserRegistration` - Tracks user registration state and invitation relationships
- Models use `UserOneToOneMixin` for relationship to AUTH_USER_MODEL

### Settings Configuration

Settings are managed through `DF_AUTH` dict in Django settings (see `df_auth/settings.py`):

**Identity Fields** - Configurable fields for user identification:
- `USER_IDENTITY_FIELDS` - Fields that uniquely identify users (default: username, email, phone_number)
- `USER_OPTIONAL_FIELDS` - Optional user profile fields
- `USER_SOCIAL_AUTH_FIELDS` - Fields populated from social auth

**Authentication Options**:
- `REQUIRED_AUTH_FIELDS` - Always required for authentication
- `OPTIONAL_AUTH_FIELDS` - Optional auth fields (otp, password)
- `OTP_AUTO_CREATE_ACCOUNT` - Auto-create user on OTP request (default: True)
- `OTP_SEND_UNAUTHORIZED_USER` - Allow OTP for non-logged-in users (default: True)
- `OTP_IDENTITY_UPDATE_FIELD` - Update user identity when OTP device confirmed (default: True)
- `DEFER_IDENTITY_UPDATE` - Defer email/phone assignment until device confirmed (default: False)

**Feature Flags**:
- `SIGNUP_ALLOWED` - Enable public registration (default: True)
- `INVITE_ALLOWED` - Enable authenticated users to invite others (default: True)

**OTP Configuration**:
- `OTP_DEVICE_MODELS` - Maps device type names to model classes (email, totp, sms)

### URL Routing

API endpoints are mounted via Django REST Framework router (`df_auth/drf/urls.py`):

```python
# Add to your root urls.py:
path('auth/', include('df_auth.drf.urls'))
```

Endpoints:
- `/auth/token/` - POST: obtain token, /refresh/, /verify/, /blacklist/
- `/auth/users/` - POST: create user, PATCH: update profile, /0/set-password/, /0/two-fa/
- `/auth/otp/` - POST: request OTP
- `/auth/otp-devices/` - GET: list devices, POST: create device, /{id}/confirm/, DELETE: remove device
- `/auth/social/` - POST: social login, /connect/ - connect social account

### 2FA Implementation

2FA is implemented through OTP devices:
1. User enables 2FA via `User2FA.is_required = True`
2. On authentication, `check_user_2fa()` (`df_auth/drf/serializers.py:42`) verifies OTP from confirmed devices
3. If 2FA required but not provided, raises `Authentication2FARequiredError` with available devices
4. Works with password auth, social login, and magic link flows

### OTP Device Lifecycle

1. **Create**: User creates device via `/otp-devices/` endpoint (unconfirmed)
2. **Challenge**: Device generates OTP token via `generate_challenge()`
3. **Confirm**: User confirms device with OTP via `/otp-devices/{id}/confirm/`
4. **Update Identity**: If `OTP_IDENTITY_UPDATE_FIELD=True`, user's email/phone updated from confirmed device
5. **Use**: Confirmed devices can authenticate user or satisfy 2FA requirement

### Flexible Identity Fields

The package supports configurable user identity fields via `USER_IDENTITY_FIELDS`:
- Default: username, email, phone_number
- Can be restricted (e.g., username-only) to allow duplicate emails/phones
- Serializers validate uniqueness only for configured identity fields (`df_auth/drf/serializers.py:342-397`)
- Username auto-populated from first available identity field if not provided (`df_auth/drf/serializers.py:406`)

## Testing Architecture

Tests use pytest-django with Django's APITestCase (`tests/test_app/tests.py`):
- Test app defines custom User model (`tests/test_app/models.py`)
- Test settings in `tests/settings.py` configure all backends and apps
- Tests cover: OTP devices, user registration, token auth, 2FA, social login, feature flags
- Use `api_settings` override pattern for testing different configurations (see `UserViewSetWithUsernameOnlyIdentityFieldAPITest`)

## Code Style

- **Formatting**: Black with max line length 88
- **Linting**: Ruff with line length 79, enabled rules: E, F, I, W, A, B, Q, C, S
- **Type Checking**: mypy with django-stubs plugin
- **Pre-commit hooks**: Runs black, ruff, mypy automatically

Ruff ignores:
- B008 (function call in default argument)
- E501 (line too long - handled by black)
- S101 (use of assert - allowed in tests)
- A003 (builtin attribute shadowing)
- B904 (raise without from inside except)

## Important Patterns

### Dynamic Serializer Fields

Serializers use `build_fields()` helper to dynamically construct fields from settings:

```python
def build_fields(fields: Dict[str, str], **kwargs) -> Dict[str, serializers.Field]:
    return {name: import_string(klass)(**kwargs) for name, klass in fields.items()}
```

This allows runtime field configuration based on `DF_AUTH` settings.

### Backend Method Dispatch

`AuthBackendSerializer` (`df_auth/drf/serializers.py:115`) iterates through `AUTHENTICATION_BACKENDS` calling specified method:
- Set `backend_method_name` on serializer subclass
- Backend method called with serializer attrs + context
- First backend to return a user wins

### OTP Challenge Pattern

OTP backends follow consistent pattern:
1. `generate_challenge()` - Find/create user, create/get device, send OTP
2. Device's `generate_challenge()` - Generate token, send via channel (email/SMS)
3. `authenticate()` - Verify token against device
4. `update_user_identity_field()` - Sync confirmed device identity to user model

### Deferred Identity Update Pattern

When `DEFER_IDENTITY_UPDATE=True`, email/phone fields are deferred until device confirmation:

**Implementation** (`df_auth/drf/serializers.py:405-452`):
1. `UserIdentitySerializer.create()` checks if field is NOT in `USER_IDENTITY_FIELDS`
2. If deferred, field is popped from `validated_data` and stored separately
3. User created without email/phone fields (they remain blank/null)
4. OTP device created with the deferred email/phone value
5. When device confirmed, `OTPDeviceConfirmSerializer.update()` (line 313-319) updates user fields

**Use Case**: Username-only identity with email verification
- User registers with username (unique) + email (not unique)
- Multiple users can register with same unconfirmed email
- Only when email is verified via OTP is it assigned to user
- Prevents spam registrations and ensures email ownership

**Configuration**:
```python
DF_AUTH = {
    'USER_IDENTITY_FIELDS': {'username': '...'},  # Only username is unique
    'USER_OPTIONAL_FIELDS': {'email': '...'},     # Email is optional
    'DEFER_IDENTITY_UPDATE': True,                # Don't save email until confirmed
    'OTP_IDENTITY_UPDATE_FIELD': True,            # Update from confirmed device
}
```

### Validation-Only ViewSets

`ValidationOnlyCreateViewSet` pattern returns 200 OK instead of 201 Created:
- Used for `TokenViewSet` and `OTPViewSet`
- Semantically correct for operations that validate credentials vs creating resources

## Package Dependencies

Core dependencies (see `pyproject.toml`):
- Django >4 (tested with 4.2)
- djangorestframework >=3
- djangorestframework-simplejwt (JWT tokens)
- django-otp, django-otp-twilio (OTP/2FA)
- social-auth-app-django (social login)
- django-phonenumber-field[phonenumbers] (phone validation)
- django-df-remote-config (remote configuration)
- django-df-api-drf (DRF utilities)

## Configuration Examples

### Minimal Setup

```python
# settings.py
INSTALLED_APPS = [
    # ... Django apps
    *DF_AUTH_INSTALLED_APPS,  # from df_auth.defaults
]

AUTHENTICATION_BACKENDS = [
    'df_auth.backends.EmailOTPBackend',
    'django.contrib.auth.backends.ModelBackend',
]

# urls.py
urlpatterns = [
    path('api/v1/auth/', include('df_auth.drf.urls')),
]
```

### Custom Configuration

```python
# Restrict to username-only identity, allow duplicate emails
DF_AUTH = {
    'USER_IDENTITY_FIELDS': {
        'username': 'rest_framework.serializers.CharField',
    },
    'USER_OPTIONAL_FIELDS': {
        'email': 'rest_framework.serializers.CharField',
        'password': 'rest_framework.serializers.CharField',
    },
    'OTP_AUTO_CREATE_ACCOUNT': False,  # Require manual registration
    'SIGNUP_ALLOWED': False,  # Invite-only
}
```

## Common Development Tasks

### Adding a New OTP Device Type

1. Create Django OTP device model or use existing
2. Add to `DF_AUTH['OTP_DEVICE_MODELS']` mapping
3. If needed, create backend subclassing `BaseOTPBackend`
4. Set `identity_field`, `device_identity_field`, `DeviceModel`
5. Override `send_challenge()` if custom delivery needed
6. Add to `AUTHENTICATION_BACKENDS`

### Customizing User Registration

Override `UserIdentitySerializer.create()` or extend the serializer:
- Add custom validation in `validate_<field>()` methods
- Modify `USER_OPTIONAL_FIELDS` to add custom fields
- Hook into `UserRegistration` model for invitation tracking

### Testing Configuration Changes

Use the override pattern in test setUp/tearDown:

```python
def setUp(self):
    api_settings.SETTING_NAME = new_value

def tearDown(self):
    api_settings.SETTING_NAME = DEFAULTS["SETTING_NAME"]
```

## Migration Notes

The package includes migrations for `User2FA` and `UserRegistration` models. Custom user models in consuming projects need their own migrations for OTP device relationships.
