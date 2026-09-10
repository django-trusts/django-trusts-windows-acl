"""PostgreSQL-first settings for the bounded Windows ACL evaluator.

  DATABASE_URL=postgres://USER:PASS@127.0.0.1:5432/DB \\
    python manage.py test winfs
"""

import os
from pathlib import Path

import dj_database_url

BASE_DIR = Path(__file__).resolve().parent.parent

SECRET_KEY = os.environ.get(
    "SECRET_KEY",
    "django-trusts-windows-acl-not-for-production",
)
DEBUG = os.environ.get("DEBUG", "1") == "1"
ALLOWED_HOSTS = [
    host.strip()
    for host in os.environ.get("ALLOWED_HOSTS", "localhost,127.0.0.1,testserver").split(",")
    if host.strip()
]

CSRF_TRUSTED_ORIGINS = [
    origin.strip()
    for origin in os.environ.get("CSRF_TRUSTED_ORIGINS", "").split(",")
    if origin.strip()
]

# Match django-trusts: keep AutoField so models do not switch to BigAutoField.
DEFAULT_AUTO_FIELD = "django.db.models.AutoField"

# Kernel-only install. Bare "trusts" is invalid after the kernel/Zero
# split (KernelConfig.default = False). Do not add django-trusts-zero:
# this consumer uses honest Context registration only.
INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "trusts.apps.KernelConfig",
    "winfs.apps.WinfsConfig",
]

# Ordinary username/password auth. Trusts system checks run through
# KernelConfig.ready(), not through an authentication backend.
AUTHENTICATION_BACKENDS = [
    "django.contrib.auth.backends.ModelBackend",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "config.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "config" / "templates"],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

WSGI_APPLICATION = "config.wsgi.application"

_DEFAULT = "postgres://winfs:winfs@127.0.0.1:5432/winfs"
_url = os.environ.get("DATABASE_URL") or os.environ.get("WINFS_DATABASE_URL") or _DEFAULT
if not _url.startswith(("postgres://", "postgresql://")):
    _url = os.environ.get("WINFS_DATABASE_URL") or _DEFAULT

DATABASES = {
    "default": dj_database_url.parse(_url, conn_max_age=0),
}

LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True

STATIC_URL = "static/"
STATIC_ROOT = BASE_DIR / "static"

LOGIN_URL = "/accounts/login/"
LOGIN_REDIRECT_URL = "/winfs/"
LOGOUT_REDIRECT_URL = "/accounts/login/"
