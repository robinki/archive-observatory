import json
import re
from json import JSONDecodeError
from os import environ
import logging

import chardet
from django.contrib.gis.geoip2 import GeoIP2
from django.http.request import HttpHeaders
from geoip2.errors import AddressNotFoundError

from control_server.core import extract_ip_address, SERVER_ADDRESS, SERVER_ADDRESS_REGEX
from control_server.time import now
from honeypot.models import AccessLog

logger = logging.getLogger(__name__)
geo_ip2 = GeoIP2()


def parse_http_headers(headers: HttpHeaders):
    headers_dict = {"HTTP_PREFIX": headers.HTTP_PREFIX}

    for key, value in headers._store.items():
        if isinstance(value, tuple):
            headers_dict[value[0]] = value[1]
        else:
            headers_dict[key] = str(value)

    return headers_dict


class AccessLogMiddleware(object):
    def __init__(self, get_response=None):
        self.get_response = get_response

    def __call__(self, request):
        # You can only read .body ONCE. This is enforced by Django.
        body = request.body

        # pretty log entire request with request line, headers and body length
        logger.debug(f"ACCESS_LOG: {request.method} {request.path} {request.scheme}")
        for key, value in request.headers.items():
            logger.debug(f"{key}: {value}")
        logger.debug(f"Body length: {len(body)}")

        response = self.get_response(request)

        # to reduce the amount of stored logs, do not log requests from authenticated users
        if (
            request.user.is_authenticated
            or request.path.lstrip("/").startswith("api/")
            or request.path.lstrip("/").startswith("login/")
        ):
            return response

        remove_list = ["password"]
        log = {
            "ip_address": extract_ip_address(request),
            "scheme": request.headers.get("X-Real-Proto", request.META.get("HTTP_X_REAL_PROTO", "")),
            "method": str(request.method),
            "path": str(request.path),
            "headers": json.dumps(parse_http_headers(request.headers)),
            "referrer": str(request.META.get("HTTP_REFERER", "")),
        }

        meta = {
            key: str(value)
            for (key, value) in request.META.items()
            if (
                key.lower() not in remove_list
                and not key.startswith("wsgi")
                and not key.startswith("gunicorn")
                and not key.startswith("HTTP_JA4")  # no duplicates
                and not key.startswith("HTTP_JA3")  # no duplicates
                and environ.get(key) != value
            )
        }
        log["meta"] = json.dumps(meta)

        # try to decode the body
        # we first try utf-8 and latin-1 and then guess with chardet
        try:
            log["body"] = json.dumps(body.decode("utf-8"))
        except UnicodeDecodeError:
            try:
                log["body"] = json.dumps(body.decode("latin-1"))
            except UnicodeDecodeError:
                guessed_encoding = chardet.detect(body)
                try:
                    log["body"] = json.dumps(body.decode(guessed_encoding))
                except UnicodeDecodeError:
                    log["body"] = body
        except Exception as e:
            logger.error(f"Unexpected error decoding body: {e}", exc_info=True)

        # cookies
        if request.COOKIES:
            cookies = {
                key: str(value)
                for (key, value) in request.COOKIES.items()
                if key.lower() not in remove_list
            }
            log["cookies"] = json.dumps(cookies)

        log["user"] = request.user if request.user.is_authenticated else None
        log["timestamp"] = str(now())
        log["absolute_url"] = str(request.build_absolute_uri()[:1024])

        http_host = request.META["HTTP_HOST"]
        log["http_host"] = str(http_host)

        subdomain = re.split(SERVER_ADDRESS_REGEX, http_host)[0].strip(".")
        log["subdomain"] = subdomain if subdomain != SERVER_ADDRESS else ""

        try:
            city = geo_ip2.city(log["ip_address"])
            log["location_data"] = json.dumps(city)
            log["location"] = f'{city.get("city", "")}/{city.get("country_name", "")}/{city.get("continent_name", "")}'
        except AddressNotFoundError as e:
            # logger.warning(f"No location found for {log['ip_address']}: {e}", exc_info=True)
            pass
        except Exception as e:
            logger.error(f"Unexpected error caught getting location data for {log['ip_address']}: {e}", exc_info=True)

        response_dict = {}
        for attr in ["status_code", "reason_phrase", "status_text", "content_type", "charset"]:
            if hasattr(response, attr):
                response_dict[attr] = getattr(response, attr)

        if getattr(response, "status_code") > 200 and hasattr(response, "content"):
            response_dict["content"] = getattr(response, "content").decode('UTF-8')

        if hasattr(response, "cookies"):
            try:
                response_dict["cookies"] = json.dumps(response.cookies)
            except JSONDecodeError:
                pass
            except Exception as e:
                logger.error(f"Unexpected error caught getting cookies data for {response.cookies}: {e}", exc_info=True)

        log["response"] = json.dumps(response_dict)

        # TLS Fingerprinting
        ja3_header = request.headers.get("JA3")
        if ja3_header:
            try:
                ja3_dict = json.loads(ja3_header)
                log["ja3_fingerprint"] = ja3_dict.get("ja3")
                log["ja3_data"] = json.dumps(ja3_dict)
            except JSONDecodeError as e:
                logger.warning(f"JSON decode error extracting JA3 TLS fingerprints: {ja3_header}")
            except Exception as e:
                logger.error(f"Unexpected error extracting JA3 TLS fingerprints: {e}", exc_info=True)

        ja4_header = request.headers.get("JA4")
        if ja4_header:
            try:
                ja4_dict = json.loads(request.headers.get("JA4", "{}"))
                log["ja4_fingerprint"] = ja4_dict["ja4"]
                log["ja4_data"] = json.dumps(ja4_dict)
            except JSONDecodeError as e:
                logger.warning(f"JSON decode error extracting JA4 TLS fingerprints: {ja4_header}")
            except Exception as e:
                logger.error(f"Unexpected error extracting JA4 TLS fingerprints: {e}", exc_info=True)

        try:
            AccessLog(**log).save()
        except Exception as e:
            logger.error(f"Error saving access log {e}", exc_info=True)

        return response
