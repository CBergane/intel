from django.contrib import admin
from django.urls import include, path

urlpatterns = [
    path("boreal-admin/", admin.site.urls),
    path("api/v1/", include("intel.api_v1.urls")),
    path("", include(("intel.admin_urls", "intel_admin"), namespace="intel_admin")),
    path("", include("intel.urls")),
]
