from django.contrib import admin
from django.db import ProgrammingError
from django.urls import include, path, re_path
from backend import settings

from . import views
from control_server.views import ApiLoginView

handler404 = views.handler404
handler500 = views.handler500

try:
    urlpatterns = []

    if settings.DJANGO_ADMIN_ENABLE:
        urlpatterns = urlpatterns + [
            re_path(r"^admin/", admin.site.urls),
        ]

    urlpatterns = urlpatterns + [
        # view for API login using BasicAuthentication
        re_path(r"^api-login/", ApiLoginView.as_view()),

        # control server api
        re_path(r"^api/", include("control_server.urls")),

        # rest authentication
        path("", include("rest_framework.urls", namespace="rest_framework")),

        # all other urls lead to the honeypot
        path("", include("honeypot.urls")),
    ]
except ProgrammingError:
    urlpatterns = []
