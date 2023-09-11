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

Registration
Signup
2FA Management
