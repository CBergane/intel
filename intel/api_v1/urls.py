from django.urls import path, re_path

from . import views


app_name = "api_v1"

urlpatterns = [
    path("health/", views.health, name="health"),
    path("signals/", views.signals, name="signals"),
    re_path(r"^(?P<path>.*)$", views.not_found),
]
