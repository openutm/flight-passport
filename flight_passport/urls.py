"""flight_passport URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/3.0/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""

# import os

import django.views.defaults as default_views
from django.conf import settings as settings

# from django.conf.urls import handler400, handler403, handler404, handler500
from django.contrib import admin
from django.urls import include, path, re_path

# from django.views.generic import TemplateView
# from dotenv import find_dotenv, load_dotenv
from oauth2_provider import views as oauth_views

from vault import views as vault_views

# handler404 = vault_views.NotFoundView.as_view()
# handler500 = vault_views.ErrorView.get_rendered_view()

urlpatterns = []
if settings.SHOW_ADMIN:
    admin.site.site_header = "Flight Passport Administration"
    admin.site.site_title = "Flight Passport Administration"
    urlpatterns += [path("admin/", admin.site.urls)]


urlpatterns += [
    re_path(
        r"^o/\.well-known/openid-configuration$",
        oauth_views.ConnectDiscoveryInfoView.as_view(),
        name="oidc-connect-discovery-info",
    ),
    path(
        "o/", include("oauth2_provider.urls", namespace="oauth2_provider")
    ),  # Default non-JWT views standard OAUTH lib.
    path(
        "oauth/", include("oauth2_provider_jwt.urls", namespace="oauth2_provider_jwt")
    ),  # for JWT Based OAUTH
    path(
        "accounts/email/",
        default_views.page_not_found,
        kwargs={"exception": Exception("Page not Found")},
    ),
    path("accounts/", include("allauth.urls")),
    path("profile/", vault_views.profile, name="profile"),
    re_path(
        r"^\.well-known/jwks.json$",
        oauth_views.JwksInfoView.as_view(),
        name="jwks-info",
    ),
    re_path(
        r"^\.well-known/openid-configuration$",
        oauth_views.ConnectDiscoveryInfoView.as_view(),
        name="base-oidc-connect-discovery-info",
    ),
    path("", vault_views.HomePage.as_view(), name="home"),
    path("userinfo/", vault_views.get_user, {}, "current_user"),
]
