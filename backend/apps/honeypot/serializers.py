from rest_framework import serializers

from .models import AccessLog, Honeypage


class AccessLogListSerializer(serializers.HyperlinkedModelSerializer):
    id = serializers.ReadOnlyField()
    ip_address = serializers.ReadOnlyField()
    timestamp = serializers.DateTimeField()

    matching_experiment = serializers.HyperlinkedRelatedField(
        view_name="experiment-detail", many=False, read_only=True
    )
    matching_honeypage = serializers.HyperlinkedRelatedField(
        view_name="honeypage-detail", many=False, read_only=True
    )

    class Meta:
        model = AccessLog
        ordering = [
            "-id",
        ]
        fields = "__all__"


class AccessLogDetailSerializer(serializers.HyperlinkedModelSerializer):
    id = serializers.ReadOnlyField()
    ip_address = serializers.ReadOnlyField()
    location = serializers.ReadOnlyField()

    username = serializers.ReadOnlyField()

    matching_experiment = serializers.HyperlinkedRelatedField(
        view_name="experiment-detail", many=False, read_only=True
    )
    matching_experiment_str = serializers.ReadOnlyField()

    seconds_since_experiment = serializers.ReadOnlyField()
    human_time_since_experiment = serializers.ReadOnlyField()

    matching_honeypage = serializers.HyperlinkedRelatedField(
        view_name="honeypage-detail", many=False, read_only=True
    )
    matching_honeypage_str = serializers.ReadOnlyField()

    class Meta:
        model = AccessLog
        ordering = [
            "-id",
        ]
        # fields = "__all__"
        fields = [
            "url", "id", "source", "timestamp", "ip_address", "absolute_url",
            "user_agent", "ja3_fingerprint", "ja4_fingerprint", "location",
            "matching_experiment", "matching_experiment_str", "matching_honeypage", "matching_honeypage_str",

            "method", "referrer", "scheme", "cookies", "body", "meta", "headers",
            "ja3_data",  "ja4_data", "location_data",
            "response", "seconds_since_experiment", "human_time_since_experiment",
            "user", "username",
        ]


class HoneypageDetailSerializer(serializers.HyperlinkedModelSerializer):
    children = serializers.HyperlinkedRelatedField(
        many=True, view_name="honeypage-detail", read_only=True
    )

    link = serializers.CharField(max_length=256)

    experiment = serializers.HyperlinkedRelatedField(
        view_name="experiment-detail", many=False, read_only=True
    )

    root = serializers.HyperlinkedRelatedField(
        view_name="honeypage-detail", many=False, read_only=True
    )

    access_logs = serializers.HyperlinkedRelatedField(
        view_name="accesslog-detail", many=True, read_only=True
    )

    class Meta:
        model = Honeypage
        ordering = [
            "-created_at",
        ]
        fields = "__all__"


class HoneypageListSerializer(serializers.HyperlinkedModelSerializer):
    children = serializers.HyperlinkedRelatedField(
        many=True, view_name="honeypage-detail", read_only=True
    )

    experiment = serializers.HyperlinkedRelatedField(
        view_name="experiment-detail", many=False, read_only=True
    )

    root = serializers.HyperlinkedRelatedField(
        view_name="honeypage-detail", many=False, read_only=True
    )

    class Meta:
        model = Honeypage
        ordering = [
            "-created_at",
        ]
        fields = [
            "id", "url", "root", "subdomain", "parent", "children", "experiment"
        ]
