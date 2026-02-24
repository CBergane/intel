from django.urls import path
from . import views

app_name = "intel_admin"

urlpatterns = [
    path("admin-login/", views.admin_login_view, name="login"),
    path("logout/", views.admin_logout_view, name="logout"),

    path("ops/", views.ops_dashboard, name="ops"),
    path("admin-panel/", views.admin_panel_view, name="panel"),

    path("admin-panel/feeds/new/", views.admin_panel_feed_create, name="feed-create"),
    path("admin-panel/feeds/<int:feed_id>/edit/", views.admin_panel_feed_edit, name="feed-edit"),
    path("admin-panel/feeds/<int:feed_id>/disable/", views.admin_panel_feed_disable, name="feed-disable"),
]
