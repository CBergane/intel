from django.contrib import admin
from django.urls import include, path

urlpatterns = [
    path("boreal-admin/", admin.site.urls),
    path("", include(("intel.admin_urls", "intel_admin"), namespace="intel_admin")),
    path("", include("intel.urls")),
]
