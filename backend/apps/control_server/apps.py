import logging

from django.apps import AppConfig

logger = logging.getLogger(__name__)


class ControlServerConfig(AppConfig):
    name = "control_server"
    verbose_name = "Control Server"

    def ready(self):
        logger.info("Control Server ready")
