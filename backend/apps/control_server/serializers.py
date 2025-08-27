from django.contrib.auth.models import User
from django.contrib.auth.password_validation import validate_password
from rest_framework import serializers
from rest_framework.reverse import reverse

from control_server.models import Target, Experiment
from control_server.time import now


class UserSerializer(serializers.HyperlinkedModelSerializer):
    username = serializers.CharField()
    first_name = serializers.CharField()
    last_name = serializers.CharField()
    experiments = serializers.HyperlinkedRelatedField(
        many=True, view_name="experiment-detail", read_only=True
    )

    class Meta:
        model = User
        ordering = [
            "-pk",
        ]
        fields = ["url", "username", "first_name", "last_name", "email", "experiments", "is_superuser", "is_staff"]


class ChangePasswordSerializer(serializers.Serializer):
    model = User

    """
    Serializer for password change endpoint.
    """
    old_password = serializers.CharField(required=True)
    new_password = serializers.CharField(required=True)

    def update(self, instance, validated_data):
        super(ChangePasswordSerializer, self).update(instance, validated_data)

    def create(self, validated_data):
        super(ChangePasswordSerializer, self).create(validated_data)

    @staticmethod
    def validate_new_password(value):
        validate_password(value)
        return value


class TargetSerializer(serializers.HyperlinkedModelSerializer):
    id = serializers.ReadOnlyField()
    name = serializers.CharField(max_length=64)
    experiments = serializers.HyperlinkedRelatedField(
        many=True, view_name="experiment-detail", read_only=True
    )
    code_name = serializers.ReadOnlyField()
    source = serializers.ReadOnlyField()

    def to_representation(self, instance):
        response = super().to_representation(instance)
        if isinstance(self.instance, list):
            response["experiments"] = "[{}] Experiments".format(
                len(response["experiments"])
            )
            keys_to_remove = []
            for key in keys_to_remove:
                response.pop(key)
        return response

    @staticmethod
    def validate_name(value):
        if len(Target.objects.filter(name__iexact="value").all()) > 0:
            raise serializers.ValidationError("A target with this name already exists.")
        return value

    class Meta:
        model = Target
        ordering = ["-pk"]
        fields = "__all__"


class PkToHyperlinkRelatedField(serializers.PrimaryKeyRelatedField):
    def __init__(self, view_name, **kwargs):
        super().__init__(**kwargs)
        self.view_name = view_name

    def to_representation(self, value):
        """
        This way, a HyperlinkedRelatedField can be created with only knowing the view name and pk of the object.
        :param value:
        :return:
        """
        return reverse(self.view_name, args=(value.pk,), request=self.context['request'])


class ExperimentListSerializer(serializers.HyperlinkedModelSerializer):
    id = serializers.ReadOnlyField()
    name = serializers.CharField(max_length=1024)
    target = serializers.HyperlinkedRelatedField(many=False, view_name="target-detail", read_only=True)
    target_str = serializers.ReadOnlyField()

    honeypage = serializers.HyperlinkedRelatedField(many=False, view_name="honeypage-detail", read_only=True)

    # timestamps
    created_at = serializers.DateTimeField(read_only=True, default=serializers.CreateOnlyDefault(now))
    started_at = serializers.DateTimeField(read_only=True)
    finished_at = serializers.DateTimeField(read_only=True)

    creator = serializers.ReadOnlyField(source="creator.username")

    class Meta:
        model = Experiment
        ordering = [
            "-id",
        ]
        fields = [
            "url", "id", "name", "target", "target_str",
            "honeypage", "creator", "created_at",
            "started_at", "finished_at"
        ]


class ExperimentDetailSerializer(serializers.HyperlinkedModelSerializer):
    id = serializers.ReadOnlyField()
    name = serializers.CharField(max_length=1024)

    target_id = serializers.ReadOnlyField()
    target = serializers.HyperlinkedRelatedField(many=False, view_name="target-detail", read_only=True)
    target_str = serializers.ReadOnlyField()

    honeypage = serializers.HyperlinkedRelatedField(many=False, view_name="honeypage-detail", read_only=True)

    honeypage_link = serializers.ReadOnlyField()

    creator = serializers.ReadOnlyField(source="creator.username")

    # timestamps
    created_at = serializers.DateTimeField(read_only=True, default=serializers.CreateOnlyDefault(now))
    started_at = serializers.DateTimeField(read_only=False)
    finished_at = serializers.DateTimeField(read_only=False)

    access_logs = serializers.HyperlinkedRelatedField(
        many=True, view_name="accesslog-detail", read_only=True
    )

    def update(self, instance, validated_data):
        return super().update(instance, validated_data)

    def to_representation(self, instance):
        response = super(ExperimentDetailSerializer, self).to_representation(instance)

        for field in ["target", "honeypage"]:
            # iterate all fields of this object and add the id of some related objects
            if hasattr(instance, field):
                value = getattr(instance, field)
                if value and hasattr(value, "pk"):
                    response.update({field + "_id": value.pk})

        response.update({
                "target_name": instance.target.name
        })

        return response

    def validate(self, data):
        # object-level validation
        return data

    class Meta:
        model = Experiment
        ordering = ["-started_at"]
        fields = [
            "url", "id", "source", "name", "target", "target_id", "target_str",
            "honeypage", "honeypage_id", "honeypage_link", "creator",
            "created_at", "started_at", "finished_at",
            "access_logs","ip_addresses", "user_agents", 
            "ja4_fingerprints", "ja3_fingerprints", "locations"
        ]

class ExperimentCreateSerializer(serializers.HyperlinkedModelSerializer):
    id = serializers.ReadOnlyField()
    name = serializers.CharField(max_length=1024)

    """
    hint: we are using a trick here to allow us to GET the Hyperlink of an object,
    e.g. https://.../targets/1/; and POST only the pk (target_id=1).
    Therefore we need the HyperlinkedRelatedField read-only and an additional PrimaryKeyRelatedField with source.
    """
    target = serializers.HyperlinkedRelatedField(many=False, view_name="target-detail", read_only=True)
    target_id = serializers.PrimaryKeyRelatedField(source="target", queryset=Target.objects.all())
    target_str = serializers.ReadOnlyField()

    def validate(self, data):
        # object-level validation
        name = data.get("name", "")
        if not name:
            name = "REPLACE ME"
            data["name"] = name

        return data

    class Meta:
        model = Experiment
        ordering = ["-pk"]
        fields = ["url", "id", "name", "target", "target_id", "target_str",]
