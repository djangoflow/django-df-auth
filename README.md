=======================================
Djangoflow REST Authentication with JWT
=======================================

Opinionated Django REST auth endpoints for JWT authentication and social accounts.

------
Design
------

Djangoflow REST authentication (*dfauth* for short) is a Django module, aiming to
provide seamless authentication and authorization, integrating with popular identity
providers (e.g. Google, Facebook, Apple etc.) as well as using built-in methods like
OTP and QRCodes.

Principles
----------

* **Opinionated:** Create a set of strict guidelines to be followed by the users
  and developers. Well defined and consistent guidelines reduces errors and
  unwanted side-effects. Framework should be easy to understand, implement and maintain.

* **Secure:** Follow the industry best practices secure software development; communications;
  storage as well as long term maintenance. Always evaluate the risk and trade-offs in
  appropriate contexts.

* **Clean code:** Strictly follow DRY principle; write your code for other developers
  to understand; document and keep documentation updated; automate testing your code,
  packaging, deployments and other processes; discuss your ideas before implementing unless
  you are absolutely sure; be a good craftsmen.

* **Open:** Offer source code and related artifacts under open source licenses. Build
  and manage a collaborative community where everyone is welcome.

* **Configurable:** Provide ways to change behavior, appearance and offer extension points
  everywhere possible.

* **Reuse:** Do not reinvent the wheel. Use existing high-quality modules as much as possible.

Endpoints
---------

* `login/`
* `logout/`
* `token/verify/`
* `token/refresh/`
* `email/otp/request/`
* `email/otp/`
* `phone/otp/request/`
* `phone/otp/`
* `phone/otp/connect`
* `facebook/`
* `facebook/connect/`
* `google/`
* `google/connect/`
* `apple/`
* `apple/connect/`

Data model
----------

**Provider configuration**

* `id` PK number - database identity
* `name` text
* `provider_project` text
* `client_id` text
* `client_secret` text
* `client_secret_source` enum(PLAIN, ENVIRONMENT)
* `callback_url` text
* `enabled` bool
* `notes` text

**Group scopes**

* `id` PK number - database identity
* `group_id` FK number
* `name` text
* `scopes` json

Views and templates
-------------------

* Login
* Logout
* Token verify
* OTP email / phone

Identity provider support
-------------------------

* Google
* Facebook
* Apple
* OTP

Other modules and links out there
---------------------------------

* https://github.com/python-social-auth/social-app-django
* https://www.django-rest-framework.org/api-guide/schemas/
* https://github.com/jazzband/django-oauth-toolkit
* ~~https://github.com/st4lk/django-rest-social-auth~~
* ~~https://github.com/pennersr/django-allauth~~

Sponsors
========

[Apexive OSS](https://apexive.com)
