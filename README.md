# django-df-auth

This is a simple opinionated module that implements JWT authentication via REST API.
For more complex applications please consider using an external authentication service such as https://goauthentik.io

The module is a glue and uses:

- drf - for the API
- simplejwt - for JWT
- pysocial - for social login
- django-otp* for otp and 2fa
- twilio - for text messages

The module also provides very limited extra functionality to the packages above:

- otp devices management OTPDeviceViewSet
    - Create, Delete
- user registration and invitation methods and template
    - standard User fields = first_name, last_name, email, phone
    - extra User fields / serializer override in settings
    -
- phone number white/black listing rules (to be removed?) => registration identity blacklist?

Blacklisting:
  - phone / email registration blacklisting (e.g. premium numbers, disposable emails ) regex
  - otp sending blacklisting
  - ip address blacklisting (honey trap)
  - usernames pattern - avoid religiously offensive words


The OTP supports following flows:
- otp (email/phone/static/totp) verification - can also be used for confirming email/phone
- 2FA
- magic signin link

## Configuration

### Basic Setup

Add to `settings.py`:

```python
from df_auth.defaults import DF_AUTH_INSTALLED_APPS

INSTALLED_APPS = [
    # ... your apps
    *DF_AUTH_INSTALLED_APPS,
]

AUTHENTICATION_BACKENDS = [
    'df_auth.backends.EmailOTPBackend',
    'df_auth.backends.TwilioSMSOTPBackend',
    'django.contrib.auth.backends.ModelBackend',
    # Optional: social auth backends
    'social_core.backends.google.GoogleOAuth2',
]
```

Add to `urls.py`:

```python
urlpatterns = [
    path('api/v1/auth/', include('df_auth.drf.urls')),
]
```

### Registration Flow Configuration

#### Immediate Account Creation (Default)

By default, accounts are created immediately when users request an OTP:

```python
DF_AUTH = {
    'OTP_AUTO_CREATE_ACCOUNT': True,  # Default
    'SIGNUP_ALLOWED': True,  # Default
}
```

**Flow:**
1. User requests OTP at `/auth/otp/` with email/phone
2. User account created immediately (unverified)
3. OTP sent to email/phone
4. User authenticates with OTP to get JWT token
5. User can confirm device via `/auth/otp-devices/{id}/confirm/`

#### Verified Registration Only

To prevent account creation until OTP is confirmed, disable auto-creation:

```python
DF_AUTH = {
    'OTP_AUTO_CREATE_ACCOUNT': False,
    'SIGNUP_ALLOWED': True,
}
```

**Flow:**
1. User must first register via `/auth/users/` with email/phone/password
2. An unconfirmed OTP device is created automatically
3. User requests OTP via `/auth/otp/`
4. User confirms device via `/auth/otp-devices/{id}/confirm/`
5. User's email/phone is updated from confirmed device (if `OTP_IDENTITY_UPDATE_FIELD=True`)

This ensures users must complete the full registration flow before their identity is verified.

#### Deferred Identity Assignment (Username-only with Email Confirmation)

To allow users to register with a username but defer email/phone assignment until OTP is confirmed:

```python
DF_AUTH = {
    'USER_IDENTITY_FIELDS': {
        'username': 'rest_framework.serializers.CharField',
    },
    'USER_OPTIONAL_FIELDS': {
        'email': 'rest_framework.serializers.CharField',
        'phone_number': 'phonenumber_field.serializerfields.PhoneNumberField',
        'password': 'rest_framework.serializers.CharField',
    },
    'DEFER_IDENTITY_UPDATE': True,  # Defer email/phone until device confirmed
    'OTP_IDENTITY_UPDATE_FIELD': True,  # Update user from confirmed device
}
```

**Flow:**
1. User registers: `POST /auth/users/` with `{ username: "john", email: "john@example.com", password: "..." }`
2. User created with `username="john"`, `email=""` (blank!) ✅
3. EmailDevice created with `email="john@example.com"`, `confirmed=False` ✅
4. User requests OTP: `POST /auth/otp/` with `{ email: "john@example.com" }`
5. OTP sent to john@example.com ✅
6. User confirms: `POST /auth/otp-devices/{id}/confirm/` with `{ otp: "123456" }`
7. Device marked `confirmed=True` ✅
8. User's `email` field NOW updated to "john@example.com" ✅

**Benefits:**
- Email/phone not saved to user model until verified
- Multiple users can register with the same unconfirmed email (no uniqueness constraint)
- Only confirmed email/phone is assigned to the user
- Prevents spam registrations with disposable emails
- Username remains the unique identity field

#### Invite-Only Registration

Disable public signups and require authenticated users to invite:

```python
DF_AUTH = {
    'SIGNUP_ALLOWED': False,  # Public signup disabled
    'INVITE_ALLOWED': True,   # Default - authenticated users can invite
}
```

**Flow:**
1. Unauthenticated users cannot POST to `/auth/users/`
2. Authenticated users can create invitations via `/auth/users/`
3. Created user has `UserRegistration.invited_by` tracking inviter

### OTP Configuration

```python
DF_AUTH = {
    # Update user's email/phone when OTP device is confirmed
    'OTP_IDENTITY_UPDATE_FIELD': True,  # Default

    # Allow OTP requests from non-authenticated users
    'OTP_SEND_UNAUTHORIZED_USER': True,  # Default

    # Available OTP device types
    'OTP_DEVICE_MODELS': {
        'email': 'django_otp.plugins.otp_email.models.EmailDevice',
        'totp': 'django_otp.plugins.otp_totp.models.TOTPDevice',
        'sms': 'otp_twilio.models.TwilioSMSDevice',
    },
}
```

### Identity Field Configuration

Configure which fields uniquely identify users:

```python
DF_AUTH = {
    # Default: email, phone, and username are all identity fields
    'USER_IDENTITY_FIELDS': {
        'username': 'rest_framework.serializers.CharField',
        'email': 'rest_framework.serializers.CharField',
        'phone_number': 'phonenumber_field.serializerfields.PhoneNumberField',
    },
}
```

**Username-only identity** (allow duplicate emails/phones):

```python
DF_AUTH = {
    'USER_IDENTITY_FIELDS': {
        'username': 'rest_framework.serializers.CharField',
    },
    'USER_OPTIONAL_FIELDS': {
        'email': 'rest_framework.serializers.CharField',
        'phone_number': 'phonenumber_field.serializerfields.PhoneNumberField',
        'password': 'rest_framework.serializers.CharField',
    },
}
```

### 2FA Configuration

2FA is controlled per-user via the `User2FA` model:

```python
# Enable 2FA for a user
from df_auth.models import User2FA
User2FA.objects.create(user=user, is_required=True)

# Via API
PATCH /api/v1/auth/users/0/two-fa/
{
    "is_required": true
}
```

When 2FA is enabled:
- User must provide valid OTP from a confirmed device
- Works with password auth, social login, and magic links
- API returns available devices if 2FA required but not provided

### Twilio Configuration

Configure Twilio for SMS OTP:

```python
OTP_TWILIO_ACCOUNT = 'your-account-sid'
OTP_TWILIO_AUTH = 'your-auth-token'
OTP_TWILIO_FROM = 'your-twilio-phone-number'
OTP_TWILIO_TOKEN_VALIDITY = 300  # 5 minutes
```

### Social Auth Configuration

Example Google OAuth2 setup:

```python
SOCIAL_AUTH_GOOGLE_OAUTH2_KEY = 'your-client-id'
SOCIAL_AUTH_GOOGLE_OAUTH2_SECRET = 'your-client-secret'

# Fields to populate from social auth
DF_AUTH = {
    'USER_SOCIAL_AUTH_FIELDS': {
        'first_name': 'rest_framework.serializers.CharField',
        'last_name': 'rest_framework.serializers.CharField',
    },
}
```

## API Endpoints

### Authentication
- `POST /auth/token/` - Obtain JWT token (username/email/phone + password/otp)
- `POST /auth/token/refresh/` - Refresh JWT token
- `POST /auth/token/verify/` - Verify JWT token
- `POST /auth/token/blacklist/` - Blacklist JWT token

### User Management
- `POST /auth/users/` - Register new user or invite user (if authenticated)
- `GET /auth/users/0/` - Get current user profile
- `PATCH /auth/users/0/` - Update user profile
- `POST /auth/users/0/set-password/` - Change password
- `GET /auth/users/0/two-fa/` - Get 2FA status
- `PATCH /auth/users/0/two-fa/` - Update 2FA requirement

### OTP
- `POST /auth/otp/` - Request OTP (email or SMS)

### OTP Devices
- `GET /auth/otp-devices/` - List user's OTP devices
- `POST /auth/otp-devices/` - Create OTP device (email, sms, totp)
- `GET /auth/otp-devices/{id}/?type={type}` - Get device details
- `POST /auth/otp-devices/{id}/confirm/?type={type}` - Confirm device with OTP
- `DELETE /auth/otp-devices/{id}/?type={type}` - Delete device

### Social Authentication
- `POST /auth/social/` - Login with social provider (google-oauth2, facebook, apple)
- `POST /auth/social/connect/` - Connect social account (requires authentication)
