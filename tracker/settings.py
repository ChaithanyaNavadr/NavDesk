# ...existing settings...

from issues.settings import BASE_DIR


INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'tracker',
]

# ...existing settings...

AUTH_USER_MODEL = 'tracker.UserDetail'  # If using custom user model

# JWT Settings
JWT_ALGORITHM = 'HS256'
JWT_EXPIRATION_DELTA = 24  # hours

# Email settings (update these with your email configuration)
EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = 'your-smtp-server'
EMAIL_PORT = 587
EMAIL_USE_TLS = True
EMAIL_HOST_USER = 'chaitanyakanchi978@gmail.com'
EMAIL_HOST_PASSWORD = 'vtualbaslxnchrbd'

# ...rest of settings...

STATIC_URL = 'static/'
STATICFILES_DIRS = [
    BASE_DIR / "static",
]

STATIC_ROOT = BASE_DIR / "staticfiles"

# ...rest of settings...

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [
            BASE_DIR / 'templates',
            BASE_DIR / 'tracker' / 'templates',
        ],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
                'django.template.context_processors.static',
            ],
        },
    },
]

# ...rest of settings...
