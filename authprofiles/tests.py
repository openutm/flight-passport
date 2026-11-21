import os
from unittest import mock

from django.core.exceptions import ValidationError
from django.test import SimpleTestCase

from authprofiles import adapter, constants


class CleanEmailTests(SimpleTestCase):
    def test_clean_email_allows_signup_when_domain_whitelist_unset(self):
        with mock.patch.dict(os.environ):
            os.environ.pop(constants.DOMAIN_WHITELIST, None)
            adapter.PassportAccountAdapter().clean_email("pilot@gmail.com")

    def test_clean_email_accepts_whitelisted_domain(self):
        with mock.patch.dict(os.environ, {constants.DOMAIN_WHITELIST: "gmail.com;example.com"}):
            self.assertEqual(
                adapter.PassportAccountAdapter().clean_email("pilot@gmail.com"),
                "pilot@gmail.com",
            )

    def test_clean_email_rejects_non_whitelisted_domain(self):
        with mock.patch.dict(os.environ, {constants.DOMAIN_WHITELIST: "example.com"}):
            with self.assertRaises(ValidationError):
                adapter.PassportAccountAdapter().clean_email("pilot@gmail.com")
