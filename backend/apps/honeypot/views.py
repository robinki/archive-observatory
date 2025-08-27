import json
import os.path
import re
import sys
import traceback
from collections import defaultdict
from typing import Optional
import logging
from urllib.parse import urlsplit

import django_filters
from django.conf import settings
from django.contrib.gis.geoip2 import GeoIP2
from django.http import HttpResponse, JsonResponse
from django.shortcuts import render
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from django.views.generic import TemplateView
from django.views.generic.base import ContextMixin
from django_filters import rest_framework as filters
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import viewsets
from rest_framework.authentication import SessionAuthentication, TokenAuthentication
from rest_framework.decorators import action
from rest_framework.filters import OrderingFilter
from rest_framework.pagination import PageNumberPagination
from rest_framework.permissions import IsAdminUser, IsAuthenticated
from rest_framework.response import Response
from ua_parser import user_agent_parser

from control_server.core import SERVER_ADDRESS, extract_ip_address
from .models import Honeypage, AccessLog
from .serializers import HoneypageDetailSerializer, AccessLogListSerializer, AccessLogDetailSerializer, HoneypageListSerializer

logger = logging.getLogger(__name__)

geo_ip2 = GeoIP2()

MIME_TYPES = {
    "css": "text/css",
    "js": "text/javascript",
    "umd.min.js": "text/javascript",
    "png": "image/png",
    "jpg": "image/jpg",
    "ico": "image/x-icon",
    "pdf": "application/pdf",
    "gif": "image/gif",
    "html": "text/html",
}

# pattern for the real ip header
REAL_IP_PATTERN = re.compile(r"'X-Real-Ip': '([.0-9]+)'")  # for setups with a Proxy

books = {}
book_mapping = {}


def default_view(request, args=None):
    return render(request, "apps/base.html", {"request": request})


def extract_subdomain_and_path_from_request(url):
    pattern = re.compile(
        # r"^https?://(?P<subdomain>[\w-]+).{server_address}/(?P<path>[\w/-]+)?/?(?:[\w\-_]+\.\w+)?/?$".format(
        r"^https?://(?P<subdomain>[\w-]+).{server_address}/(?P<path>[\w/-]+)?(?P<filename>(/[\w\-_]+\.\w+)?/?)?$".format(
            server_address=SERVER_ADDRESS
        ),
        re.IGNORECASE
    )
    match = pattern.search(url)
    group_dict = match.groupdict() if match else defaultdict()

    subdomain = group_dict.get("subdomain") or ""
    path = (group_dict.get("path") or "").strip("/")

    return subdomain, path


def split_url(url):
    parsed_url = urlsplit(url)

    path = parsed_url.path
    query = parsed_url.query
    fragment = parsed_url.fragment

    pattern_str = r"^https?://(?P<subdomain>[\w-]+)?.?{server_address}/?"
    pattern = re.compile(pattern_str.format(server_address=SERVER_ADDRESS), re.IGNORECASE)
    match = pattern.search(url)
    group_dict = match.groupdict() if match else defaultdict(str)

    subdomain = group_dict.get("subdomain", "")

    if '/' in path:
        path, filename = path.rsplit('/', 1)
    else:
        if "." in path:
            filename = path
            path = ""
        else:
            filename = ""

    return subdomain or "", path or "", filename or ""


def split_url_manual(url):
    pattern_str = (
        r"^https?://(?P<subdomain>[\w-]+)?.?{server_address}/?"
        r"(?P<path>[^/#?]+)?"
        r"(?P<filename>(/[^/#?]+\.\w+)?/?)?"
        r"(?P<query>\?[^#]*)?"
        r"(?P<fragment>#.*)?$"
    )
    pattern = re.compile(
        pattern_str.format(
            server_address=SERVER_ADDRESS
        ), re.IGNORECASE
    )
    match = pattern.search(url)
    group_dict = match.groupdict() if match else defaultdict()

    subdomain = group_dict.get("subdomain") or ""
    path = group_dict.get("path") or ""
    filename = group_dict.get("filename") or ""
    return subdomain, path, filename


class CSRFExemptMixin(ContextMixin):
    @method_decorator(csrf_exempt)
    def dispatch(self, *args, **kwargs):
        return super(CSRFExemptMixin, self).dispatch(*args, **kwargs)


class BookHoneyPageView(CSRFExemptMixin, TemplateView):
    template_name = "apps/honeypot/linked_honeypage.html"

    @property
    def name(self):
        return "BookHoneyPage"

    def get(self, request, slug=None, *args, **kwargs):
        honeypage: Optional[Honeypage] = None
        subdomain, path = extract_subdomain_and_path_from_request(request.build_absolute_uri())

        if subdomain or path:
            honeypage: Honeypage = Honeypage.objects.filter(
                subdomain__iexact=subdomain,
                path__iregex=r"{}/?".format(path)
            ).first()

        parent = None
        children = []
        if honeypage:
            children = honeypage.children.all()
            parent = honeypage.parent
            book_id = honeypage.book_id
            color = honeypage.color
        else:
            # deterministically select correct book and color
            book_id, color = Honeypage.url_parts_to_book_and_color(subdomain, path)

        book_data = Honeypage.books.get("book_" + str(book_id), None)

        return render(
            request,
            self.template_name,
            {
                "title": (subdomain or "") + (("/" + path) if path else ""),
                "request": request,
                "children": children,
                "parent": parent,
                "registered": honeypage is not None,

                "url": request.build_absolute_uri().replace("http://", "https://"),
                "subdomain": subdomain,
                "path": path,

                "book_id": book_id,
                "book_gutenberg_id": book_data["gutenberg_id"] if book_data else "",
                "book_title": book_data["title"] if book_data else "",
                "book_author": book_data["author"] if book_data else "",
                "book_release_date": book_data["release_date"] if book_data else "",
                "book_language": book_data["language"] if book_data else "",
                "book_original_publication": book_data["original_publication"] if book_data else "",
                "book_credits": book_data["credits"] if book_data else "",
                "book_summary": book_data["summary"] if book_data else "",
                # "book_first_page": book_data["first_page"] if book_data else "",
                "book_cover_path": ("covers/cover_" + str(book_data["gutenberg_id"]) + ".jpg") if book_data else "",
                "book_url": book_data["url"] if book_data else "",

                "color": color,
            },
        )


@csrf_exempt
@require_http_methods(["GET", "HEAD"])
def resource_view(request, resource_name=None, file_ending=None, *args, **kwargs):
    # check resource type
    mime_type = MIME_TYPES.get(file_ending)
    subdomain, path, filename = split_url(request.build_absolute_uri())
    filename_no_ending = filename.replace(f".{file_ending}", "").replace("/", "")

    logger.debug(
        f'Resource requested: "{subdomain}" (subdomain), "{path}" (path), "{filename_no_ending}" (filename), "{file_ending}" (file_ending)'
    )

    honeypage = Honeypage.objects.filter(subdomain__iexact=subdomain).first()
    book_id = honeypage.book_id if honeypage else Honeypage.url_parts_to_book_and_color(subdomain, path)[0]

    # fetch js scripts
    if mime_type == MIME_TYPES.get("js"):
        file_path = "run/static/scripts/{}.{}".format(filename_no_ending, file_ending)
        if os.path.isfile(file_path):
            try:
                with open(file_path, "rb") as f:
                    return HttpResponse(f.read(), content_type=mime_type, status=200)
            except IOError:
                pass

    if re.match(r"/?cover.jpg", filename):
        book_data = Honeypage.books.get(f"book_{book_id}", {})
        cover_path = book_data.get("cover_image", "cover_0.jpg")
        cover_file_path = f"run/static/honeypage/covers/{cover_path}"
        try:
            with open(cover_file_path, "rb") as f:
                return HttpResponse(f.read(), content_type="image/jpg", status=200)
        except IOError as e:
            print("IOError:", e)

    # try to fetch honeypage files by name
    file_path = "run/static/honeypage/{}.{}".format(filename_no_ending, file_ending)
    if mime_type and os.path.isfile(file_path):
        try:
            with open(file_path, "rb") as f:
                return HttpResponse(f.read(), content_type=mime_type, status=200)
        except IOError:
            pass

    # unsupported type or resource does not exist
    print(
        "[INFO] {}.{} was requested, but can't be served.".format(
            resource_name, file_ending
        )
    )

    response = render(request, "404.html", {})
    response.status_code = 404
    return response


class AccessLogFilter(filters.FilterSet):
    id__gt = django_filters.NumberFilter(field_name="id", lookup_expr="gt")
    id__lte = django_filters.NumberFilter(field_name="id", lookup_expr="lte")

    class Meta:
        model = AccessLog
        fields = []


class LargeResultsSetPagination(PageNumberPagination):
    page_size = 100
    page_size_query_param = 'page_size'
    max_page_size = 10000


class AccessLogViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = AccessLog.objects.all()
    serializer_class = AccessLogListSerializer

    pagination_class = LargeResultsSetPagination
    authentication_classes = (TokenAuthentication, SessionAuthentication,)

    permission_classes = (
        IsAdminUser,
        IsAuthenticated,
    )

    filter_backends = [DjangoFilterBackend, OrderingFilter]
    filterset_class = AccessLogFilter
    filterset_fields = ("id",)
    ordering_fields = ["id"]

    def get_serializer_class(self):
        # detail view is requested via "?detail"
        if self.action == 'retrieve' or "detail" in self.request.query_params.keys():
            return AccessLogDetailSerializer
        elif self.action == 'list':
            return AccessLogListSerializer

        # default
        return AccessLogListSerializer

    @action(detail=True)
    def similar(self, request, pk=None):
        """
        API endpoint to list all `AccessLogs` that come from the same ip.
        """
        log = AccessLog.objects.filter(pk=pk).first()
        similar_logs = self.filter_queryset(AccessLog.objects.filter(ip_address=log.ip_address))

        page = self.paginate_queryset(similar_logs)
        if page is not None:
            serializer = self.get_serializer(page, many=True)
            return self.get_paginated_response(serializer.data)

        serializer = self.get_serializer(similar_logs, many=True)
        return Response(serializer.data)

    @action(detail=False)
    def unauthenticated(self, request):
        """
        API endpoint to list all `AccessLogs` with no authenticated user.
        """
        logs = self.filter_queryset((AccessLog.objects.filter(user__isnull=True)))
        page = self.paginate_queryset(logs)
        if page is not None:
            serializer = self.get_serializer(page, many=True)
            return self.get_paginated_response(serializer.data)

        serializer = self.get_serializer(logs, many=True)
        return Response(serializer.data)

    @action(detail=False)
    def authenticated(self, request):
        """
        API endpoint to list all `AccessLogs` from an authenticated user.
        """
        logs = self.filter_queryset(AccessLog.objects.filter(user__isnull=False))
        page = self.paginate_queryset(logs)
        if page is not None:
            serializer = self.get_serializer(page, many=True)
            return self.get_paginated_response(serializer.data)

        serializer = self.get_serializer(logs, many=True)
        return Response(serializer.data)

    @action(detail=False)
    def foreign(self, request):
        """
        API endpoint to list all `AccessLogs` where the IP address is not in [`127.0.0.1`, ].
        """
        logs = self.filter_queryset(AccessLog.objects.exclude(ip_address__in=["127.0.0.1", ]))
        page = self.paginate_queryset(logs)
        if page is not None:
            serializer = self.get_serializer(page, many=True)
            return self.get_paginated_response(serializer.data)

        serializer = self.get_serializer(logs, many=True)
        return Response(serializer.data)


class HoneypageViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = Honeypage.objects.all()
    serializer_class = HoneypageDetailSerializer
    authentication_classes = (TokenAuthentication, SessionAuthentication,)

    permission_classes = (
        IsAdminUser,
        IsAuthenticated,
    )

    def get_serializer_class(self):
        if self.action == 'retrieve' or "detail" in self.request.query_params.keys():
            return HoneypageDetailSerializer
        elif self.action == 'list':
            return HoneypageListSerializer
        return HoneypageListSerializer

    @action(detail=False)
    def root_honeypages(self, request):
        """
        API endpoint to list all `Honeypages` without a parent.
        """
        serializer = HoneypageListSerializer(
            Honeypage.objects.filter(parent=None), many=True, context={"request": request}
        )
        return Response(serializer.data)

    # *** API Endpoints regarding AccessLogs ***
    @action(detail=True)
    def get_access_logs(self, request, pk=None):
        """
        Lists all AccessLog instances where subdomain and path match this HoneyPage.
        Excludes logs from authenticated users.
        """
        return self._craft_paginated_access_log_response(
            Honeypage.objects.filter(pk=pk).first().access_logs, request
        )

    @action(detail=True)
    def get_access_logs_authenticated(self, request, pk=None):
        """
        API endpoint to list all AccessLog instances for this experiment from authenticated users.
        """
        return self._craft_paginated_access_log_response(
            Honeypage.objects.filter(pk=pk).first().access_logs_authenticated, request
        )

    def _craft_paginated_access_log_response(self, queryset, request):
        context = {"request": request}
        page = self.paginate_queryset(queryset)
        if page is not None:
            serializer = AccessLogListSerializer(page, many=True, context=context)
            return self.get_paginated_response(serializer.data)

        serializer = AccessLogListSerializer(queryset, many=True, context=context)
        return Response(serializer.data)
