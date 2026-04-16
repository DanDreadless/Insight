import os
from pathlib import Path
from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent

load_dotenv(BASE_DIR.parent / '.env')

DEBUG = os.environ.get('DEBUG', 'False') == 'True'

SECRET_KEY = os.environ.get('SECRET_KEY', '')
if not SECRET_KEY:
    if DEBUG:
        import warnings
        SECRET_KEY = 'insecure-dev-only-key-do-not-use-in-production'
        warnings.warn(
            'SECRET_KEY is not set — using an insecure development key. '
            'Set SECRET_KEY in your .env file before deploying.',
            RuntimeWarning,
            stacklevel=2,
        )
    else:
        from django.core.exceptions import ImproperlyConfigured
        raise ImproperlyConfigured(
            'SECRET_KEY must be set in production (DEBUG=False). '
            'Add SECRET_KEY to your .env file or environment.'
        )

ALLOWED_HOSTS = os.environ.get('ALLOWED_HOSTS', 'localhost,127.0.0.1').split(',')

INSTALLED_APPS = [
    'django.contrib.contenttypes',
    'django.contrib.auth',
    'django.contrib.staticfiles',
    'rest_framework',
    'corsheaders',
    'drf_spectacular',
    'scanner',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'whitenoise.middleware.WhiteNoiseMiddleware',
    'corsheaders.middleware.CorsMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'insight.middleware.CSPMiddleware',
]

ROOT_URLCONF = 'insight.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.request',
            ],
        },
    },
]

WSGI_APPLICATION = 'insight.wsgi.application'

# Database
_db_url = os.environ.get('DATABASE_URL', 'sqlite:///db.sqlite3')
if _db_url.startswith('sqlite:///'):
    _db_path = _db_url[len('sqlite:///'):]
    if not os.path.isabs(_db_path):
        _db_path = str(BASE_DIR / _db_path)
    DATABASES = {
        'default': {
            'ENGINE': 'django.db.backends.sqlite3',
            'NAME': _db_path,
        }
    }
elif _db_url.startswith('postgres'):
    # SEC-23: use urlparse instead of a hand-rolled regex so passwords
    # containing '@' (URL-encoded as %40) are handled correctly.
    from urllib.parse import urlparse as _urlparse, unquote as _unquote
    _parsed_db = _urlparse(_db_url)
    if not _parsed_db.hostname:
        raise ValueError(f'Cannot parse DATABASE_URL: {_db_url}')
    DATABASES = {
        'default': {
            'ENGINE': 'django.db.backends.postgresql',
            'NAME': _parsed_db.path.lstrip('/'),
            'USER': _parsed_db.username or '',
            'PASSWORD': _unquote(_parsed_db.password or ''),
            'HOST': _parsed_db.hostname,
            'PORT': str(_parsed_db.port or 5432),
        }
    }
else:
    raise ValueError(f'Unsupported DATABASE_URL scheme: {_db_url}')

# Cache / Redis
REDIS_URL = os.environ.get('REDIS_URL', 'redis://localhost:6379/0')

try:
    import redis as _redis_test
    CACHES = {
        'default': {
            'BACKEND': 'django.core.cache.backends.redis.RedisCache',
            'LOCATION': REDIS_URL,
        }
    }
except Exception:
    CACHES = {
        'default': {
            'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',
            'LOCATION': 'unique-snowflake',
        }
    }

# SEC-11: Warn if production Redis is not using TLS + auth.
# In production, set REDIS_URL=rediss://:password@host:6380/0
if not DEBUG and not REDIS_URL.startswith('rediss://'):
    import warnings as _warnings
    _warnings.warn(
        'SEC-11: REDIS_URL is not using TLS (rediss://). '
        'Production deployments must use rediss:// with authentication.',
        RuntimeWarning,
        stacklevel=2,
    )

# Celery
CELERY_BROKER_URL = REDIS_URL
CELERY_RESULT_BACKEND = REDIS_URL
CELERY_ACCEPT_CONTENT = ['json']
CELERY_TASK_SERIALIZER = 'json'
CELERY_RESULT_SERIALIZER = 'json'
CELERY_BROKER_CONNECTION_RETRY_ON_STARTUP = True

SCAN_TIMEOUT_SECONDS = int(os.environ.get('SCAN_TIMEOUT_SECONDS', '60'))
CELERY_TASK_TIME_LIMIT = SCAN_TIMEOUT_SECONDS + 30
CELERY_TASK_SOFT_TIME_LIMIT = SCAN_TIMEOUT_SECONDS

# Static files
STATIC_URL = '/static/'
STATIC_ROOT = BASE_DIR / 'staticfiles'
STATICFILES_STORAGE = 'whitenoise.storage.CompressedManifestStaticFilesStorage'

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# CORS
CORS_ALLOWED_ORIGINS = os.environ.get(
    'CORS_ALLOWED_ORIGINS', 'http://localhost:5173'
).split(',')
CORS_ALLOW_CREDENTIALS = False

# REST Framework
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': [],
    'DEFAULT_PERMISSION_CLASSES': [],
    'UNAUTHENTICATED_USER': None,
    'DEFAULT_RENDERER_CLASSES': [
        'rest_framework.renderers.JSONRenderer',
    ],
    'DEFAULT_THROTTLE_CLASSES': [
        'rest_framework.throttling.ScopedRateThrottle',
    ],
    'DEFAULT_THROTTLE_RATES': {
        # scan_submit has no throttle_scope — rate limiting is handled by the
        # custom Redis-based per-IP counter in ScanSubmitView (RATE_LIMIT_SCANS_PER_HOUR).
        'scan_status': '600/hour',   # 10 polls/min per IP
        'health': '60/minute',       # SEC-13: health endpoint rate limiting
    },
    'DEFAULT_SCHEMA_CLASS': 'drf_spectacular.openapi.AutoSchema',
}

# Security headers (always-on)
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = 'DENY'
SECURE_REFERRER_POLICY = 'strict-origin-when-cross-origin'
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = 'Strict'

# Production hardening — only active when DEBUG=False to avoid breaking local dev
if not DEBUG:
    SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')
    SECURE_SSL_REDIRECT = True
    SECURE_HSTS_SECONDS = 31536000
    SECURE_HSTS_INCLUDE_SUBDOMAINS = True
    SECURE_HSTS_PRELOAD = True
    SESSION_COOKIE_SECURE = True
    CSRF_COOKIE_SECURE = True

# CSP (used by middleware)
CSP_DEFAULT_SRC = "'self'"

# DRF Spectacular
SPECTACULAR_SETTINGS = {
    'TITLE': 'Insight API',
    'DESCRIPTION': 'Passive web threat scanning platform.',
    'VERSION': '1.0.0',
    'SERVE_INCLUDE_SCHEMA': False,
}

# Scanner config
MAX_SCAN_RESOURCES = int(os.environ.get('MAX_SCAN_RESOURCES', '50'))
RATE_LIMIT_SCANS_PER_HOUR = int(os.environ.get('RATE_LIMIT_SCANS_PER_HOUR', '5'))

# Reverse-proxy trust config (SEC-01)
# Set to the number of trusted proxy hops in front of this app.
# 0 = always use REMOTE_ADDR (safe default for direct or unknown deployments).
# 1 = one trusted proxy (e.g. Cloudflare or Nginx) prepends one XFF entry.
# Never set higher than the actual number of proxies you control.
TRUSTED_PROXY_COUNT = int(os.environ.get('TRUSTED_PROXY_COUNT', '0'))

USE_TZ = True
TIME_ZONE = 'UTC'
LANGUAGE_CODE = 'en-us'
