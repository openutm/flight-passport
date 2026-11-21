from os import environ as env

from django.core.exceptions import ImproperlyConfigured
from django.forms import ValidationError
from dotenv import find_dotenv, load_dotenv

from allauth.account.adapter import DefaultAccountAdapter

from . import constants

ENV_FILE = find_dotenv()
if ENV_FILE:
    load_dotenv(ENV_FILE)

ALLOW_ANY_DOMAIN = {"*", "all"}


class PassportAccountAdapter(DefaultAccountAdapter):
    def clean_email(self, email):
        domain_whitelist = env.get(constants.DOMAIN_WHITELIST)
        allowed_domains = {
            entry.strip().lower()
            for entry in (domain_whitelist or "").split(";")
            if entry.strip()
        }
        if allowed_domains & ALLOW_ANY_DOMAIN:
            return email
        if not allowed_domains:
            raise ImproperlyConfigured(
                "DOMAIN_WHITELIST is unset or empty; configure it first with a "
                "';'-separated list of allowed domains, or '*;' / 'all;' to allow "
                "sign-ups from any email address."
            )
        domain = email.split("@")[1].lower()
        if domain in allowed_domains:
            return email
        raise ValidationError("You are restricted from registering. Please contact admin.")
