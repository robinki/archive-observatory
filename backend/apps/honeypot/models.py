import json
import os
import random
import re
import uuid
from itertools import chain
import hashlib
import time

from django.db import models, IntegrityError
from django.utils.timesince import timesince

from django.conf import settings
from control_server.core import SERVER_ADDRESS, PROTOCOL
from backend.core import PrefixedUUIDModel


class AccessLog(PrefixedUUIDModel):
    absolute_url = models.TextField(null=False, blank=True)

    http_host = models.CharField(max_length=512, null=False, blank=True)
    subdomain = models.CharField(max_length=64, null=False, blank=True, default="")
    path = models.CharField(max_length=128, null=False, blank=True)

    ip_address = models.CharField(max_length=45, null=False, blank=True)
    user = models.ForeignKey("auth.User", on_delete=models.PROTECT, null=True, blank=True)

    ja3_data = models.TextField(null=True, blank=True)
    ja3_fingerprint = models.CharField(max_length=100, null=True, blank=True)
    ja4_data = models.TextField(null=True, blank=True)
    ja4_fingerprint = models.CharField(max_length=100, null=True, blank=True)

    referrer = models.CharField(max_length=512, null=True, blank=True)
    method = models.CharField(max_length=8, null=False, blank=True)
    scheme = models.CharField(max_length=24, null=True, blank=True)

    headers = models.TextField(null=True, blank=True)
    cookies = models.TextField(null=True, blank=True)
    body = models.TextField(null=True, blank=True)
    meta = models.TextField(null=True, blank=True)

    timestamp = models.DateTimeField(null=False, blank=True)
    location = models.CharField(max_length=512, null=True, blank=True)
    location_data = models.TextField(verbose_name="GeoIP 2 Location", null=True, blank=True)

    response = models.TextField(verbose_name="Response", blank=True)

    class Meta:
        app_label = "honeypot"
        db_table = "honeypot_access_logs"
        verbose_name = "Access Log"
        default_permissions = ["view"]
        ordering = [
            "-timestamp",
        ]

    def save(self, *args, **kwargs):
        if not self.id:
            self.id = f'{settings.UUID_PREFIX}{uuid.uuid4()}'
        super().save(*args, **kwargs)

    @property
    def user_agent(self):
        try:
            obj = json.loads(self.headers)
            return obj.get("User-Agent", None)
        except Exception:
            print("Error parsing user agent for Access Log", self.id)
            return None

    @property
    def username(self):
        return self.user.username if self.user else None

    @property
    def honeypage(self):
        """
        Matching Honeypage (matched on subdomain).
        """
        return Honeypage.objects.filter(subdomain__iexact=self.subdomain).first()

    @property
    def experiment(self):
        """
        Matching experiment (based on Honeypage match).
        """
        return self.honeypage.root.experiment if self.honeypage else None

    @property
    def experiment_seconds_since(self):
        if self.experiment:
            # get the most relevant timestamp from the experiment
            experiment_timestamp = self.experiment.finished_at or self.experiment.started_at or self.experiment.created_at
            return (self.timestamp - experiment_timestamp).total_seconds()

        return None

    @property
    def experiment_human_time_since(self):
        if self.experiment:
            experiment_timestamp = self.experiment.finished_at or self.experiment.started_at or self.experiment.created_at
            return timesince(experiment_timestamp, self.timestamp)

        return ""
    

class Honeypage(PrefixedUUIDModel):
    created_at = models.DateTimeField(auto_now_add=True, blank=False)
    protocol = models.CharField(max_length=5, default="http")
    subdomain = models.CharField(max_length=128, default="")
    path = models.CharField(max_length=128, default="", blank=True)
    book_id = models.IntegerField()
    color = models.CharField(max_length=7)

    parent = models.ForeignKey(
        "honeypot.Honeypage",
        on_delete=models.PROTECT,
        related_name="children",
        parent_link=True,
        blank=True,
        null=True,
    )

    MAX_BOOKS = 0  # Will be updated on startup
    books = {}  # Will be updated on startup

    class Meta:
        app_label = "honeypot"
        db_table = "honeypot_honeypages"
        default_permissions = ["view"]
        verbose_name = "Honeypage"
        ordering = [
            "-created_at",
        ]
        unique_together = ('source', 'book_id', 'color')  # Ensure book_id and color_id pairs are unique

    @classmethod
    def set_books_from_file(cls, filepath):
        if os.path.exists(filepath):
            with open(filepath, 'r') as file:
                data = json.load(file)
                cls.books = data['books']
                cls.MAX_BOOKS = max(int(book.split('_')[1]) for book in data['books'])
        else:
            raise FileNotFoundError(f"{filepath} not found.")

    @classmethod
    def url_parts_to_book_and_color(cls, _subdomain, _path):
        # Query the database to find existing book_id and color combinations
        used_combinations = set(Honeypage.objects.values_list('book_id', 'color'))

        # Start with the original input
        original_input = re.sub(r'[._/]', '', str(_subdomain) + str(_path))
        _input = original_input
        increment = 0

        while True:
            # Create a hash of the input
            hash_object = hashlib.md5(str(_input).encode())
            hash_hex = hash_object.hexdigest()

            # Convert the first 6 characters of the hash to an integer
            hash_int = int(hash_hex[:6], 16)

            # Map the integer to a valid book ID
            book_id = hash_int % Honeypage.MAX_BOOKS  # Ensure book_id is within the range

            # Map the integer to RGB values
            r = (hash_int >> 16) & 0xFF  # Extract the red component
            g = (hash_int >> 8) & 0xFF  # Extract the green component
            b = hash_int & 0xFF  # Extract the blue component

            # Format the color in HTML notation
            color = f'#{r:02X}{g:02X}{b:02X}'

            # Check if the book_id and color combination is unique
            if (book_id, color) not in used_combinations:
                # Save the combination to the database if needed
                return book_id, color

            # If a collision is found, increment the input
            increment += 1
            _input = f"{original_input}_{increment}"

    def __iter__(self):
        """
        Implement the iterator protocol.
        Test with `print(list(iter(root_honeypage)))`
        :return:
        """
        for child in chain(*map(iter, list(self.children.all()))):
            yield child
        yield self

    @property
    def all_children_subdomains(self):
        paths = [self.subdomain]

        for child in self.children.all():
            paths += child.all_child_subdomains

        return paths

    @property
    def root(self):
        if not self.parent:
            return self
        else:
            return self.parent.root

    @property
    def experiment(self):
        return self.root.experiment

    @property
    def link(self):
        return "{}://{}.{}/{}".format(
            self.protocol, self.subdomain, SERVER_ADDRESS, self.path + "/" if self.path != "" else ""
        )

    @property
    def book_title(self):
        return Honeypage.books.get("book_" + str(self.book_id), {})["title"]

    @property
    def access_logs(self):
        """
        Returns AccessLogs that match this HoneyPage's path and subdomain.
        :return:
        """
        return AccessLog.objects.filter(user__isnull=True, subdomain=self.subdomain)

    @staticmethod
    def generate_unique_subdomain(extension_name: str = ""):
        nano_second_time = str(time.time_ns())
        _hash = hashlib.sha224()
        _hash.update(extension_name.encode() + nano_second_time.encode())
        if settings.SUBDOMAIN_PREFIX != "":
            _subdomain = settings.SUBDOMAIN_PREFIX + "-" + _hash.hexdigest()
        else:
            _subdomain = _hash.hexdigest()

        # make subdomains shorter
        hash_characters = list(_subdomain)
        random_chars = random.sample(hash_characters, min(12, len(hash_characters)))

        # Concatenate to form the new subdomain
        short_subdomain = ''.join(random_chars[:6]) + "-" + ''.join(random_chars[6:])

        return short_subdomain

    @staticmethod
    def generate_honeypage():
        while True:
            try:
                subdomain = Honeypage.generate_unique_subdomain()
                path = ""
                book_id, color = Honeypage.url_parts_to_book_and_color(subdomain, path)

                honeypage = Honeypage(
                    subdomain=subdomain,
                    path=path,
                    protocol=PROTOCOL,
                    parent=None,
                    book_id=book_id,
                    color=color
                )
                honeypage.save()
                return honeypage
            except IntegrityError:
                continue  # Retry generating a unique subdomain
            except Exception:
                continue

    def attach_branches(self, n_layers=2, n_children_per_page=2):
        def build_tree(root, i=0):
            if i < n_layers:
                for _ in range(n_children_per_page):
                    success = False
                    while not success:
                        try:
                            subdomain = Honeypage.generate_unique_subdomain()
                            path = ""
                            book_id, color = Honeypage.url_parts_to_book_and_color(subdomain, path)

                            node_honeypage = Honeypage(
                                subdomain=subdomain,
                                path=path,
                                protocol=PROTOCOL,
                                parent=root,
                                book_id=book_id,
                                color=color
                            )
                            node_honeypage.save()
                            build_tree(node_honeypage, i + 1)
                            success = True
                        except IntegrityError:
                            continue  # Retry generating a unique subdomain
                        except Exception:
                            continue

        build_tree(self)

    @staticmethod
    def generate_branched_honeypage(n_layers=2, n_children_per_page=2):
        honeypage = Honeypage.generate_honeypage()
        Honeypage.attach_branches(honeypage, n_layers, n_children_per_page)
        return honeypage
