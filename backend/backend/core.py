import uuid
from django.db import models
from django.conf import settings


class PrefixedUUIDField(models.CharField):
    def __init__(self, *args, **kwargs):
        kwargs['max_length'] = settings.MAX_UUID_PREFIX_LENGTH + 32  # prefix + 32 characters for UUID
        super().__init__(*args, **kwargs)

    def pre_save(self, model_instance, add):
        value = super().pre_save(model_instance, add)
        if not value:
            value = settings.UUID_PREFIX + str(uuid.uuid4())
            setattr(model_instance, self.attname, value)
        return value


class PrefixedUUIDModel(models.Model):
    id = PrefixedUUIDField(primary_key=True, editable=False)
    source = models.CharField(max_length=64, null=False, blank=True, default=settings.NODE_NAME)

    class Meta:
        abstract = True

    def save(self, *args, **kwargs):
        if not self.id:
            self.id = f'{settings.UUID_PREFIX}{uuid.uuid4()}'
        super().save(*args, **kwargs)
