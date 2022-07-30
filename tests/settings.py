DEBUG = True
SECRET_KEY = "secret_key"
ROOT_URLCONF = 'df_auth.urls'
INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'django.contrib.sites',
    'rest_framework',
    'rest_framework.authtoken',

    'social_django',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]


STATIC_URL = '/static/'


SOCIAL_AUTH_JSONFIELD_ENABLED = True

AUTHENTICATION_BACKENDS = (
    'social_core.backends.google.GoogleOAuth2',
    'social_core.backends.facebook.FacebookOAuth2',
    'django.contrib.auth.backends.ModelBackend',
)

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': 'apex_db.sqlite3',
    }
}

SOCIAL_AUTH_GOOGLE_OAUTH2_KEY = '150035990900-7moqv8je1epjt3hd107dr3v6vp56cn5b.apps.googleusercontent.com'
SOCIAL_AUTH_GOOGLE_OAUTH2_SECRET = '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'

SOCIAL_AUTH_FACEBOOK_KEY = '623807988780280'
SOCIAL_AUTH_FACEBOOK_SECRET = '220059b1c1757ba3c3df7ab2c58cd061'
SOCIAL_AUTH_FACEBOOK_SCOPE = ['email']
SOCIAL_AUTH_FACEBOOK_PROFILE_EXTRA_PARAMS = {
    'fields': 'id,name,email', 
}
REST_SOCIAL_OAUTH_REDIRECT_URI = '/api/auth/social/callback/'
REST_SOCIAL_OAUTH_REDIRECT = "http://localhost:8000/api/auth/social/callback/"
SITE_ID=1