from os import environ as env

from django.forms import ValidationError
from dotenv import find_dotenv, load_dotenv

from allauth.account.adapter import DefaultAccountAdapter

from . import constants

ENV_FILE = find_dotenv()
if ENV_FILE:
    load_dotenv(ENV_FILE)


class PassportAccountAdapter(DefaultAccountAdapter):
    def clean_email(self, email):
        domain_whitelist = env.get(constants.DOMAIN_WHITELIST)
        if domain_whitelist is None:
            return email
        domain = email.split("@")[1]
        white_listed_domain = [i for i in domain_whitelist.split(";")]

        if domain in white_listed_domain:
            return email
        else:
            raise ValidationError("You are restricted from registering. Please contact admin.")
