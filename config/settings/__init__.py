import os

if os.getenv("DJANGO_ENV", "dev").lower() == "prod":
    from .prod import *  # noqa: F401,F403
else:
    from .dev import *  # noqa: F401,F403
