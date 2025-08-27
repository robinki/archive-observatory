import django_filters
import logging
from django.contrib.auth import login
from django.contrib.auth.models import User
from django.http import JsonResponse, HttpResponse
from django.shortcuts import redirect
from django_filters import rest_framework as filters
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import viewsets, status
from rest_framework.authentication import BasicAuthentication, SessionAuthentication, TokenAuthentication
from rest_framework.authtoken.models import Token
from rest_framework.authtoken.views import ObtainAuthToken
from rest_framework.decorators import action
from rest_framework.exceptions import APIException
from rest_framework.filters import OrderingFilter
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from control_server.time import now
from honeypot.models import Honeypage
from honeypot.serializers import AccessLogDetailSerializer
from honeypot.views import LargeResultsSetPagination
from .core import get_codename
from .models import Target, Experiment
from .permissions import IsOwnerOrReadOnly
from .serializers import UserSerializer, TargetSerializer, ExperimentDetailSerializer, ChangePasswordSerializer, ExperimentListSerializer, ExperimentCreateSerializer

logger = logging.getLogger(__name__)

class ApiLoginView(APIView):
    """
    Here authentication with username and password is possible.
    When successful, a secure http only "sessionid" cookie will automatically be set.
    """
    authentication_classes = (BasicAuthentication,)

    @staticmethod
    def post(request, *args, **kwargs):
        # use django.contrib.auth.login
        print("API login view request received", request)
        login(request, request.user)
        # user = request.user
        return Response("Successfully authenticated.", 200)


class AuthTokenViewSet(ObtainAuthToken):
    authentication_classes = (BasicAuthentication,)  # this can never include SessionAuthentication

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(
            data=request.data, context={"request": request}
        )
        if serializer.is_valid(raise_exception=False):
            user = serializer.validated_data["user"]
            token, created = Token.objects.get_or_create(user=user)

            return JsonResponse(
                {
                    "username": user.username,
                    "token": token.key,
                    "user_id": user.pk,
                    "email": user.email,
                }
            )
        return HttpResponse(serializer.errors, status=401)


class UserViewSet(viewsets.ModelViewSet):
    """ API endpoint that allows users to be viewed or edited. """

    permission_classes = (IsAuthenticated,)
    authentication_classes = (SessionAuthentication, TokenAuthentication)

    queryset = User.objects.order_by("id")
    serializer_class = UserSerializer

    @action(detail=False)
    def me(self, request):
        if request.user.is_authenticated and request.user.id:
            return redirect("user-detail", request.user.id)

        return Response("User not authenticated", 403)


class UpdatePassword(APIView):
    """
    An endpoint for changing password.
    """
    permission_classes = (IsAuthenticated,)

    def get_object(self, queryset=None):
        return self.request.user

    def put(self, request, *args, **kwargs):
        self.object = self.get_object()
        serializer = ChangePasswordSerializer(data=request.data)

        if serializer.is_valid():
            # Check old password
            old_password = serializer.data.get("old_password")
            if not self.object.check_password(old_password):
                return Response({"status": ["Wrong password."]}, status=status.HTTP_400_BAD_REQUEST)
            # set_password also hashes the password that the user will get
            self.object.set_password(serializer.data.get("new_password"))
            self.object.save()
            return Response({"status": "Password changed."}, status=status.HTTP_204_NO_CONTENT)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class TargetViewSet(viewsets.ModelViewSet):
    """ API endpoint for Targets """

    permission_classes = (IsAuthenticated,)
    authentication_classes = (SessionAuthentication, TokenAuthentication,)

    queryset = Target.objects.all()
    serializer_class = TargetSerializer

    pagination_class = LargeResultsSetPagination
    pagination_class.page_size = 100

    def perform_create(self, serializer):
        name = serializer.validated_data.get("name").lower()
        code_names = map(lambda x: x["code_name"], Target.objects.all().values("code_name"))
        code_name = get_codename(name)

        while code_name in code_names:
            code_name = get_codename()

        serializer.save(code_name=code_name)

class ExperimentFilter(filters.FilterSet):
    id__gt = django_filters.NumberFilter(field_name="id", lookup_expr="gt")
    id__lte = django_filters.NumberFilter(field_name="id", lookup_expr="lte")

    class Meta:
        model = Experiment
        fields = []


class ExperimentViewSet(viewsets.ModelViewSet):
    """ API endpoint for Experiments. """

    permission_classes = (IsAuthenticated, IsOwnerOrReadOnly,)
    authentication_classes = (SessionAuthentication, TokenAuthentication,)

    queryset = Experiment.objects.all()
    serializer_class = ExperimentDetailSerializer

    filter_backends = [DjangoFilterBackend, OrderingFilter]
    filterset_class = ExperimentFilter
    filterset_fields = ("name",)
    ordering_fields = ["name", "started_at", "finished_at"]

    def get_serializer_class(self):
        # detail view is requested via "?detail"
        if self.action == "create":
            return ExperimentCreateSerializer
        if self.action in ["retrieve"] or "detail" in self.request.query_params.keys():
            return ExperimentDetailSerializer
        elif self.action == "list":
            return ExperimentListSerializer

        # default
        return ExperimentDetailSerializer

    # *** Manual Experiments ***
    def get_queryset(self):
        queryset = super().get_queryset()

        if self.action in ["finish_manually"]:
            queryset = queryset.filter(manual=True)

        return queryset

    @action(detail=True, methods=["get", "post"])
    def set_started(self, request, pk=None):
        """
        Mark a manual experiment as started.
        :param request:
        :param pk:
        :return:
        """
        experiment = Experiment.objects.filter(pk=pk).first()
        if not experiment.started_at:
            experiment.started_at = now()
            experiment.save()
            return Response({"message": "changed", "started_at": experiment.started_at})

        return Response({"message": "unchanged", "started_at": experiment.started_at})

    @action(detail=True, methods=["get", "post"])
    def set_finished(self, request, pk=None):
        """
        Mark a manual experiment as finished.
        :param request:
        :param pk:
        :return:
        """
        experiment = Experiment.objects.filter(pk=pk).first()
        if not experiment.finished_at:
            experiment.finished_at = now()
            experiment.save()
            return Response({"message": "changed", "finished_at": experiment.finished_at})

        return Response({"message": "unchanged", "finished_at": experiment.finished_at})

    # *** Hooks ***
    def create(self, request, *args, **kwargs):
        response = super(ExperimentViewSet, self).create(request, *args, **kwargs)
        # here may be placed additional operations for
        # extracting id of the object and using reverse()
        experiment_id = response.data.get("id", None)
        if experiment_id:
            return redirect("experiment-detail", experiment_id)

        return response

    def perform_create(self, serializer):
        target_name = serializer.validated_data.get("target", None)

        if not target_name:
            raise APIException("ExperimentDetail can't be created, target is not set.")

        honeypage = Honeypage.generate_branched_honeypage()

        serializer.save(
            creator=self.request.user,
            honeypage=honeypage,
        )

    def perform_update(self, serializer):
        # Get the original instance
        instance = self.get_object()
        validated_data = serializer.validated_data

        logger.debug(f"Received update request with data: {serializer.validated_data}")
        logger.debug(f"Initial data: {serializer.initial_data}")

        # Only allow these fields to be updated
        allowed_fields = {'started_at', 'finished_at'}
        update_fields = set(validated_data.keys())

        # Check if any non-allowed fields are being updated
        if not update_fields.issubset(allowed_fields):
            raise APIException("Only started_at and finished_at fields can be updated.")

        # Set the allowed fields from validated data
        if 'started_at' in validated_data:
            logger.debug(f"{instance.id} Setting started_at to {validated_data['started_at']}")
            instance.started_at = validated_data['started_at']
        if 'finished_at' in validated_data:
            logger.debug(f"{instance.id} Setting finished_at to {validated_data['finished_at']}")
            instance.finished_at = validated_data['finished_at']

        # Save only the modified fields
        instance.save(update_fields=list(update_fields))

    # *** API Endpoints listing Experiments ***
    @action(detail=False)
    def get_running_experiments(self, request):
        """
        API endpoint to list all Experiments that are running.
        """
        return self._craft_paginated_experiment_response(
            self.filter_queryset(Experiment.get_running_experiments())
        )

    # *** API Endpoints regarding Logs ***
    @action(detail=True)
    def get_access_logs(self, request, pk=None):
        """
        API endpoint to list all AccessLog instances where subdomain and path match the experiment.
        """
        experiment = Experiment.objects.filter(pk=pk).first()
        access_logs = experiment.access_logs
        return self._craft_paginated_access_log_response(access_logs, request)

    # *** Methods ***
    def _craft_paginated_experiment_response(self, queryset):
        page = self.paginate_queryset(queryset)
        if page is not None:
            serializer = self.get_serializer(page, many=True)
            return self.get_paginated_response(serializer.data)

        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data)

    def _craft_paginated_access_log_response(self, queryset, request):
        context = {"request": request}
        page = self.paginate_queryset(queryset)
        if page is not None:
            serializer = AccessLogDetailSerializer(page, many=True, context=context)
            return self.get_paginated_response(serializer.data)

        serializer = AccessLogDetailSerializer(queryset, many=True, context=context)
        return Response(serializer.data)