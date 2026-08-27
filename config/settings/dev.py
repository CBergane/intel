from .base import *  # noqa: F401,F403

DEBUG = True

# Development must not depend on a collectstatic manifest, even when base
# settings loaded DEBUG=False from a production-style .env file.
STORAGES = {
    "default": {"BACKEND": "django.core.files.storage.FileSystemStorage"},
    "staticfiles": {
        "BACKEND": "django.contrib.staticfiles.storage.StaticFilesStorage"
    },
}
