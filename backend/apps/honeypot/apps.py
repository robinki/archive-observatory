import os
import logging
from pathlib import Path

from django.apps import AppConfig

logger = logging.getLogger(__name__)


class HoneypotConfig(AppConfig):
    name = "honeypot"

    def ready(self):
        # Safely get the Honeypage model
        honeypage_model = self.get_model('Honeypage')

        # Call the methods to set MAX_BOOKS and MAX_COLORS
        script_path = os.path.dirname(Path(__file__).absolute())
        books_path = os.path.join(script_path, "data/gutenberg/books.json")

        honeypage_model.set_books_from_file(books_path)
        logger.info("Honeypot ready.")
