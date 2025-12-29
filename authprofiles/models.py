import uuid

from django.db import models
from django.utils.translation import gettext_lazy as _

# Create your models here.
from oauth2_provider.models import AbstractApplication


class PassportScope(models.Model):
    uuid = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=140, help_text="e.g. dss.read.identification_service_areas")
    description = models.CharField(max_length=140)

    def __str__(self):
        return self.name

    def __repr__(self):
        return self.__str__()

    def __uniode__(self):
        return self.__str__()


class PassportAPI(models.Model):
    uuid = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    identifier = models.CharField(max_length=140, help_text="e.g. che.openskies.sh")
    name = models.CharField(max_length=140)
    scopes = models.ManyToManyField(PassportScope, related_name="api_scope", blank=True)

    def __str__(self):
        return self.name

    def __repr__(self):
        return self.__str__()

    def __uniode__(self):
        return self.__str__()


class PassportApplication(AbstractApplication):
    APPLICATION_CLASS_CHOICES = (
        (0, _("Other")),
        (1, _("Login only")),
        (2, _("Client Credentials")),
    )
    client_class = models.IntegerField(choices=APPLICATION_CLASS_CHOICES, default=0)
    audience = models.ManyToManyField(PassportAPI, related_name="application_audience", blank=True)
    subject = models.CharField(max_length=140, blank=True, help_text="add a sub claim to the token e.g. OpenUTM")
