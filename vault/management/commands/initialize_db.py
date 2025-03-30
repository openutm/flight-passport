from django.conf import settings as settings
from django.contrib.sites.models import Site
from django.core.management.base import BaseCommand


class Command(BaseCommand):
    help = "Initializes database and site in Django"

    def handle(self, *args, **options):
        print("Setting site name and domain")
        site = Site.objects.get(id=1)

        site.name = settings.JWT_ISSUER
        site.domain = settings.JWT_ISSUER_DOMAIN
        site.save()
