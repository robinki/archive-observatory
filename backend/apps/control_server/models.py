import json
import os
import re

from django.db import models
from django.db.models import Q

from backend.core import PrefixedUUIDModel
from honeypot.models import AccessLog, Honeypage

from geoip2.database import Reader as GeoIP2Reader

_db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), '../../run/geoip/')
geoip2_city_reader = GeoIP2Reader(os.path.join(_db_path, "GeoLite2-City.mmdb"))
geoip2_asn_reader = GeoIP2Reader(os.path.join(_db_path, "GeoLite2-ASN.mmdb"))


from .time import now


known_ips = {
    "senders": [
        r"127\.0\.0\.1",
    ],
    "receivers": [
        r"127\.0\.0\.1",
    ]
}

# Q filters
# Create Q objects for each regular expression in the lists
q_objects_list1 = [Q(ip_address__regex=regex) for regex in known_ips["senders"]]
q_objects_list2 = [Q(ip_address__regex=regex) for regex in known_ips["receivers"]]

# Combine the Q objects with OR for each list
q_combined_list1 = Q()
for q_object in q_objects_list1:
    q_combined_list1 |= q_object

q_combined_list2 = Q()
for q_object in q_objects_list2:
    q_combined_list2 |= q_object

# Combine the Q objects with AND for the final query
# usage: logs.exclude(known_ip_q_filter)  # to exclude all client-side requests
known_ip_q_filter = q_combined_list1 | q_combined_list2


with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "crawler-user-agents.json"), 'r') as f:
    known_crawler_ua_patterns = json.load(f)


def is_crawler_ua(ua):
    """
    Checks known crawler user agents for match with the given user-agent.
    Returns true if ua is a known crawler user-agent.

    :param ua: User-agent string to be checked
    :return: Boolean value indicating if ua is a known crawler user-agent
    """
    for entry in known_crawler_ua_patterns:
        if re.search(entry['pattern'], ua):
            return True
    return False


def matches_any_pattern(patterns, string):
    return any(re.search(pattern, string) for pattern in patterns)


class Target(PrefixedUUIDModel):
    name = models.CharField(max_length=64, blank=False, null=False)
    code_name = models.CharField(max_length=128, blank=True, null=False)

    def __str__(self):
        return self.name

    @property
    def experiments(self):
        return Experiment.objects.filter(target_id=self.id)

    class Meta:
        app_label = "control_server"
        db_table = "control_server_targets"
        verbose_name = "Target"
        ordering = ["-pk"]


class Experiment(PrefixedUUIDModel):
    name = models.CharField(max_length=1024, blank=False)
    target = models.ForeignKey(
        Target,
        related_name="experiments",
        on_delete=models.PROTECT,
        null=False,
        blank=False,
    )

    honeypage = models.OneToOneField(
        Honeypage,
        related_name="experiment",
        on_delete=models.PROTECT,
        blank=True,
        null=False,
    )

    # store the user who created this experiment
    creator = models.ForeignKey(
        "auth.User",
        related_name="experiments",
        on_delete=models.PROTECT,
        null=False,
        blank=True,
    )

    # timestamps
    created_at = models.DateTimeField(auto_now_add=True, blank=False)
    started_at = models.DateTimeField(null=True, blank=True)
    finished_at = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return "{} ({})".format(
            self.target.name,
            self.id
        )

    class Meta:
        app_label = "control_server"
        db_table = "control_server_experiments"
        verbose_name = "Experiments"
        ordering = ["-pk"]

    @property
    def honeypage_link(self):
        return self.honeypage.link if self.honeypage else None

    @property
    def target_str(self):
        return self.target.name if self.target else None

    def is_valid(self):
        """Returns True if the experiment is fully configured."""
        if not self.target:
            return False

        # true if any honeydata is attached
        return self.honeypage

    def is_started(self) -> bool:
        return self.started_at is not None and self.started_at < now()

    def is_finished(self) -> bool:
        return self.finished_at is not None

    @staticmethod
    def get_running_experiments():
        """ Returns all experiments that are already started. """
        return Experiment.objects.order_by("-started_at")

    @property
    def access_logs(self):
        """
        Returns the AccessLogs that match the Experiment's Honeypage and all children of that page.
        Returns an empty list if no Honeypage exists.
        :return: FilterSet or []
        """
        if self.honeypage:
            logs = self.honeypage.access_logs
            for page in list(iter(self.honeypage)):
                logs |= page.access_logs  # combine FilterSet
            return logs.order_by("timestamp")
        return AccessLog.objects.none()

    @property
    def ip_addresses(self):
        return list(set([log.ip_address for log in self.access_logs]))

    @property
    def user_agents(self):
        return list(set([log.user_agent for log in self.access_logs]))

    @property
    def ja4_fingerprints(self):
        return list(set([log.ja4_fingerprint for log in self.access_logs]))

    @property
    def ja3_fingerprints(self):
        return list(set([log.ja3_fingerprint for log in self.access_logs]))

    @property
    def locations(self):
        return list(set([log.location for log in self.access_logs]))
