import os
from unittest import mock

from django.core.exceptions import ImproperlyConfigured
from django.forms import ValidationError
from django.test import SimpleTestCase

from authprofiles import adapter, constants


class CleanEmailTests(SimpleTestCase):
    def test_clean_email_requires_configuration_when_unset(self):
        with mock.patch.dict(os.environ):
            os.environ.pop(constants.DOMAIN_WHITELIST, None)
            with self.assertRaises(ImproperlyConfigured):
                adapter.PassportAccountAdapter().clean_email("pilot@gmail.com")

    def test_clean_email_requires_configuration_when_no_valid_entries(self):
        for value in ("", " ", ";"):
            with self.subTest(value=value):
                with mock.patch.dict(os.environ, {constants.DOMAIN_WHITELIST: value}):
                    with self.assertRaises(ImproperlyConfigured):
                        adapter.PassportAccountAdapter().clean_email("pilot@gmail.com")

    def test_clean_email_accepts_whitelisted_domain(self):
        with mock.patch.dict(os.environ, {constants.DOMAIN_WHITELIST: "gmail.com;example.com"}):
            self.assertEqual(
                adapter.PassportAccountAdapter().clean_email("pilot@gmail.com"),
                "pilot@gmail.com",
            )

    def test_clean_email_accepts_whitelisted_domain_case_insensitively(self):
        with mock.patch.dict(os.environ, {constants.DOMAIN_WHITELIST: "GMail.com"}):
            self.assertEqual(
                adapter.PassportAccountAdapter().clean_email("pilot@GMAIL.com"),
                "pilot@GMAIL.com",
            )

    def test_clean_email_accepts_whitelisted_domain_with_spaced_entries(self):
        with mock.patch.dict(os.environ, {constants.DOMAIN_WHITELIST: " gmail.com ; example.com ;"}):
            self.assertEqual(
                adapter.PassportAccountAdapter().clean_email("pilot@gmail.com"),
                "pilot@gmail.com",
            )

    def test_clean_email_accepts_any_domain_with_star_wildcard(self):
        with mock.patch.dict(os.environ, {constants.DOMAIN_WHITELIST: "*;"}):
            self.assertEqual(
                adapter.PassportAccountAdapter().clean_email("pilot@example.org"),
                "pilot@example.org",
            )

    def test_clean_email_accepts_any_domain_with_all_wildcard(self):
        with mock.patch.dict(os.environ, {constants.DOMAIN_WHITELIST: "all;"}):
            self.assertEqual(
                adapter.PassportAccountAdapter().clean_email("pilot@example.org"),
                "pilot@example.org",
            )

    def test_clean_email_rejects_non_whitelisted_domain(self):
        with mock.patch.dict(os.environ, {constants.DOMAIN_WHITELIST: "example.com"}):
            with self.assertRaises(ValidationError):
                adapter.PassportAccountAdapter().clean_email("pilot@gmail.com")
