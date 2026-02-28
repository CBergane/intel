from django.urls import path

from . import views

app_name = "intel_admin"

urlpatterns = [
    path("admin-login/", views.admin_login_view, name="login"),
    path("logout/", views.admin_logout_view, name="logout"),
    path("ops/", views.ops_dashboard, name="ops"),
    path("admin-panel/", views.admin_panel_view, name="panel"),
    path("admin-panel/new/", views.admin_panel_feed_create, name="feed_create"),
    path("admin-panel/<int:feed_id>/edit/", views.admin_panel_feed_edit, name="feed_edit"),
    path(
        "admin-panel/<int:feed_id>/disable/",
        views.admin_panel_feed_disable,
        name="feed_disable",
    ),
    path("admin-panel/sources/", views.admin_panel_sources_list, name="sources"),
    path("admin-panel/sources/new/", views.admin_panel_source_create, name="source_create"),
    path(
        "admin-panel/sources/<int:source_id>/edit/",
        views.admin_panel_source_edit,
        name="source_edit",
    ),
    path(
        "admin-panel/sources/<int:source_id>/toggle/",
        views.admin_panel_source_toggle,
        name="source_toggle",
    ),
]
