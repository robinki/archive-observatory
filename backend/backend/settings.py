import os
import logging.config
import sys
from os.path import abspath, basename, dirname, join, normpath

# a string that specifies the kind of settings module
# "development" and "production" is allowed
SETTINGS_MODULE = os.environ.get("SETTINGS_MODULE", "development")
SUBDOMAIN_PREFIX = ""
DJANGO_LOG_LEVEL = os.environ.get("DJANGO_LOG_LEVEL", "INFO")
DJANGO_ADMIN_ENABLE = os.environ.get("DJANGO_ADMIN_ENABLE", "False") == "True"

MAX_UUID_PREFIX_LENGTH = 16
_uuid_prefix = os.environ.get("UUID_PREFIX", "")
if len(_uuid_prefix) > 0:
    if not _uuid_prefix.endswith("-"):
        _uuid_prefix += "-"
    if len(_uuid_prefix) > MAX_UUID_PREFIX_LENGTH:
        raise Exception("UUID_PREFIX is too long")
UUID_PREFIX = _uuid_prefix
NODE_NAME = os.environ.get("NODE_NAME", "")

# Toggle Debug
DEBUG = True if SETTINGS_MODULE == "development" else False

# ##### PATH CONFIGURATION ################################
# fetch Django"s project directory == BASE_DIR
DJANGO_ROOT = dirname(dirname(abspath(__file__)))

# fetch the project_root
# this is the honeymessages-docker/ folder
PROJECT_ROOT = dirname(DJANGO_ROOT)

# the name of the whole site == backend
SITE_NAME = basename(DJANGO_ROOT)

# collect media files here
MEDIA_ROOT = join(DJANGO_ROOT, "run", "media")

STATIC_ROOT = os.path.join(DJANGO_ROOT, "run", "static")

STATICFILES_DIRS = [
    os.path.join(DJANGO_ROOT, "static"),
]

# look for templates here
PROJECT_TEMPLATES = [
    join(DJANGO_ROOT, "templates"),
]

# add apps/ to the Python path
sys.path.append(normpath(join(DJANGO_ROOT, "apps")))
print(os.path.join(PROJECT_ROOT, "server.log"))
LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "handlers": {
        "logfile": {
            "class": "logging.FileHandler",
            "filename": os.path.join(PROJECT_ROOT, "server.log"),
        },
        "console": {
            "class": "logging.StreamHandler",
        },
        "mail_admins": {
           "level": "ERROR",
           "class": "django.utils.log.AdminEmailHandler",
           "include_html": True,
        }
    },
    "loggers": {
        "django": {
            "handlers": ["console", "logfile"],
            'level': DJANGO_LOG_LEVEL,
        },
        'django.request': {
            'handlers': ['console', 'logfile'],
            'level': DJANGO_LOG_LEVEL,
        },
        'backend': {
            'handlers': ['console', 'logfile'],
            'level': DJANGO_LOG_LEVEL,
        },
        'control_server': {
            'handlers': ['console', 'logfile'],
            'level': DJANGO_LOG_LEVEL,
        },
        'honeypot': {
            'handlers': ['console', 'logfile'],
            'level': DJANGO_LOG_LEVEL,
        },
    },
}

# Applying the logging configuration
logging.config.dictConfig(LOGGING)

# Use logger in settings.py
logger = logging.getLogger(__name__)

logger.debug("DEBUG " + str(DEBUG))
logger.info("MEDIA_ROOT " + MEDIA_ROOT)
logger.info("STATIC_ROOT " + STATIC_ROOT)
logger.info("STATICFILES_DIRS " + ", ".join(STATICFILES_DIRS))

# The secret key is fetched from the environment
SECRET_KEY = os.environ.get("SECRET_KEY", "TESTING_KEY_12345").strip()

ALLOWED_HOSTS = os.environ.get("DJANGO_ALLOWED_HOSTS", "*").split()
logger.info("ALLOWED_HOSTS " + ", ".join(ALLOWED_HOSTS))

PROTOCOL = os.environ.get("PROTOCOL", "http")

# allow all cors
# CORS_ORIGIN_ALLOW_ALL = False
CORS_ORIGIN_WHITELIST = os.environ.get("CORS_ORIGIN_WHITELIST", PROTOCOL + "://api.localhost").split()

CSRF_TRUSTED_ORIGINS = os.environ.get(
    "CSRF_TRUSTED_ORIGINS",
    " ".join([  # default
        "api.localhost", "localhost"
    ])
).split(" ")
logger.info("CSRF_TRUSTED_ORIGINS " + ", ".join(CSRF_TRUSTED_ORIGINS))

if SETTINGS_MODULE == "development":
    CORS_ORIGIN_ALLOW_ALL = True

# ##### DATABASE CONFIGURATION ############################
DATABASES = {
    "default": {
        "ENGINE": os.environ.get("SQL_ENGINE", default="django.db.backends.sqlite3"),
        "NAME": os.environ.get("SQL_DATABASE", default=join(DJANGO_ROOT, "run", "dev.sqlite3")),
        "USER": os.environ.get("SQL_USER", default="user"),
        "PASSWORD": os.environ.get("SQL_PASSWORD", default="password"),
        "HOST": os.environ.get("SQL_HOST", default="localhost"),
        "PORT": os.environ.get("SQL_PORT", default="5432"),
    }
}

# ##### APPLICATION CONFIGURATION #########################
INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",

    # custom apps
    "corsheaders",

    # DRF
    "rest_framework",
    "rest_framework.authtoken",
    "background_task",

    # Django
    "django_extensions",
    "django_filters",

    # Project Applications
    "control_server",
    "honeypot",
    "backend"
]

# The list of directories to search for fixtures
FIXTURE_DIRS = [
    "apps/control_server/fixtures/",
    "apps/honeypot/fixtures/"
]

REST_FRAMEWORK = {
    "DEFAULT_PAGINATION_CLASS": "rest_framework.pagination.PageNumberPagination",
    "PAGE_SIZE": 10,
    "DEFAULT_FILTER_BACKENDS": ["django_filters.rest_framework.DjangoFilterBackend"],
    "DEFAULT_AUTHENTICATION_CLASSES": [
        "rest_framework.authentication.SessionAuthentication",
        "rest_framework.authentication.TokenAuthentication",
        "rest_framework.authentication.BasicAuthentication",
    ],
    "DEFAULT_RENDERER_CLASSES": [
        "rest_framework.renderers.JSONRenderer",
        "rest_framework.renderers.BrowsableAPIRenderer",
    ],
    "DEFAULT_SCHEMA_CLASS": "rest_framework.schemas.coreapi.AutoSchema",
}

MIDDLEWARE = [
    # django middleware
    "corsheaders.middleware.CorsMiddleware",
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",

    # custom middleware
    "backend.middleware.AccessLogMiddleware",
]

APPEND_SLASH = True

# templates
TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": PROJECT_TEMPLATES,
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "backend.context_processors.export_vars",
                "django.contrib.auth.context_processors.auth",
                "django.template.context_processors.debug",
                "django.template.context_processors.i18n",
                "django.template.context_processors.media",
                "django.template.context_processors.static",
                "django.template.context_processors.tz",
                'django.template.context_processors.request',
                "django.contrib.messages.context_processors.messages",
            ],
            'builtins': [
                'honeypot.templatetags.honeypot_extra_tags'
            ]
        },
    },
]

# Internationalization
USE_I18N = False
USE_TZ = True
TIME_ZONE = 'America/New_York'

# ##### DJANGO RUNNING CONFIGURATION ######################

DEFAULT_AUTO_FIELD = 'django.db.models.AutoField'

# the default WSGI application
WSGI_APPLICATION = "%s.wsgi.application" % SITE_NAME

# the root URL configuration
ROOT_URLCONF = "%s.urls" % SITE_NAME

# Redirect to home URL after login (Default redirects to /accounts/profile/)
LOGIN_URL = "/login/"
LOGIN_REDIRECT_URL = "/api/"
LOGOUT_REDIRECT_URL = "/login/"

# the URL for static files
STATIC_URL = "run/static/"

# the URL for media files
MEDIA_URL = "run/media/"

# ##### CONTACT ############################

# the email address, these error notifications to admins come from
SERVER_EMAIL = "..."

# these persons receive error notification
ADMINS = (("...", SERVER_EMAIL),)
MANAGERS = ADMINS

# ##### SECURITY CONFIGURATION ############################

# redirects all requests to https if True
# NOTE: If nginx handles the redirects, we do not need this here!
# SECURE_SSL_REDIRECT = PROTOCOL == "https"

SESSION_COOKIE_AGE = 1209600
SESSION_COOKIE_SECURE = PROTOCOL == "https"  # if True session cookies will only be set if https is used
SESSION_COOKIE_HTTPONLY = True  # set session cookie as HTTP only
SESSION_COOKIE_DOMAIN = os.environ.get("SESSION_COOKIE_DOMAIN", "")

# Cookie Based, Browser Clearing Will lose it.
SESSION_ENGINE = "django.contrib.sessions.backends.signed_cookies"
SESSION_CACHE_ALIAS = "default"  # or comfortably anything else
CACHES = {
    'default': {
        "BACKEND": "django_redis.cache.RedisCache",
        "LOCATION": "redis://127.0.0.1:6379/1",
        "OPTIONS": {
            "CLIENT_CLASS": "django_redis.client.DefaultClient",
        }
    }
}

CSRF_COOKIE_SECURE = PROTOCOL == "https"  # if True csrf cookies will only be set if https is used
CSRF_COOKIE_HTTPONLY = True

secure_proxy_ssl_header = os.environ.get("SECURE_PROXY_SSL_HEADER", None)
if secure_proxy_ssl_header:
    # Proxy needs to set this header HTTP_X_FORWARDED_PROTO
    SECURE_PROXY_SSL_HEADER = (secure_proxy_ssl_header, PROTOCOL)

DOMAIN_NAME = os.environ.get("DOMAIN_NAME", "")
CSRF_COOKIE_DOMAIN = os.environ.get("CSRF_COOKIE_DOMAIN", "")

# GeoIP2
GEOIP_PATH = normpath(join(DJANGO_ROOT, "run", "geoip"))

X_FRAME_OPTIONS = "SAMEORIGIN"
