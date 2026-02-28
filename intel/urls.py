from django.urls import path
from . import views

urlpatterns = [
    path("", views.now_view, name="now"),
    path("active/", views.active_view, name="active"),
    path("advisories/", views.advisories_view, name="advisories"),
    path("research/", views.research_view, name="research"),
    path("sweden/", views.sweden_view, name="sweden"),
    path("feed-health/", views.feed_health_view, name="feed-health"),
    path("sources/", views.sources_view, name="sources"),
    path("about/", views.about_view, name="about"),
]