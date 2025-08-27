import os
import re
import logging
from codename import codename
from django.conf import settings

logger = logging.getLogger(__name__)

PROTOCOL = settings.PROTOCOL

LOCAL_ADDRESS = "localhost"
LOCAL_ADDRESS_REGEX = r"(?:127.0.0.1|localhost|localtest|fbi)(?:\.me|\.com)?(?:\:[0-9]{2,4})?"

REMOTE_ADDRESS = os.environ.get("DOMAIN_NAME", "localhost")  # DOMAIN_NAME
REMOTE_ADDRESS_REGEX = REMOTE_ADDRESS

SERVER_ADDRESS = LOCAL_ADDRESS if settings.DEBUG else REMOTE_ADDRESS
SERVER_ADDRESS_REGEX = LOCAL_ADDRESS_REGEX if settings.DEBUG else REMOTE_ADDRESS_REGEX

HONEYPOT_URL = (
    (PROTOCOL + "://" + LOCAL_ADDRESS)
    if settings.DEBUG
    else (PROTOCOL + "://" + REMOTE_ADDRESS)
)

PATH_REGEX = re.compile(
    r"^https?://(?:{}|{})/(.*)$".format(REMOTE_ADDRESS, LOCAL_ADDRESS_REGEX), re.I
)

assert not SERVER_ADDRESS.endswith("/"), "SERVER_ADDRESS must not end with slash."


def extract_path(url: str) -> str:
    """
    Extracts the path from the url.
    :param url:
    :return: path: str
    """
    match = PATH_REGEX.match(url)
    if match and match.group(1):
        return match.group(1)
    else:
        return ""


def extract_ip_address(request) -> str:
    """
    Extracts the IP address of the sender from the request object.
    :param request: the WSGIRequest
    :return: str
    """
    ip_address = request.headers.get("X-Real-IP", request.headers.get("X-Real-Ip", request.META.get("HTTP_X_REAL_IP", "")))

    if "," in ip_address:
        # Python will combine duplicate headers. Using the last one should be safe.
        # However, this should not happen anymore as our tlsfp uses a custom header
        ip_address = ip_address.split(",")[-1].strip()
        logger.warning(f"Multiple IP addresses found, defaulting to last one \"{ip_address}\", X-Real-Ip: {request.headers['X-Real-Ip']}")

    return ip_address


def get_codename(seed: str = None) -> str:
    return codename(id=seed, separator="-")
