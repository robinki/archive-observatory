from django.urls import include, path, re_path
from django.views.decorators.csrf import csrf_exempt
from rest_framework.routers import DefaultRouter
from rest_framework.schemas import get_schema_view

from control_server import views
from control_server.views import AuthTokenViewSet, UpdatePassword
from honeypot.views import HoneypageViewSet, AccessLogViewSet, resource_view

router = DefaultRouter()

# logs
router.register(r"access_logs", AccessLogViewSet)

# base models
router.register(r"users", views.UserViewSet)
router.register(r"targets", views.TargetViewSet)
router.register(r"experiments", views.ExperimentViewSet)

# honeydata
router.register(r"honeypages", HoneypageViewSet)

schema = get_schema_view(
    title="ControlServer API",
    description="API to interact with the ControlServer",
    version="0.0.4",
)

urlpatterns = [
    path("schema/", schema, name="openapi-schema"),
    path("token-auth/", csrf_exempt(AuthTokenViewSet.as_view())),
    path("change-password/", UpdatePassword.as_view()),

    re_path(r"(?P<resource_name>[\w-]+)\.(?P<file_ending>[\w.]+)/?$", resource_view),

    path("", include(router.urls)),
]
