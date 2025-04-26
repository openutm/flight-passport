import json
import re

import jwt
from django.contrib.auth import get_user_model
from django.contrib.auth.decorators import login_required

# from django.core.serializers import serialize
# from django.core.serializers.json import DjangoJSONEncoder
from django.http import HttpResponse
from django.shortcuts import render
from django.views.generic import TemplateView
from rest_framework import exceptions

from oauth2_provider_jwt.utils import decode_jwt_user_info


class HomePage(TemplateView):
    template_name = "passport_homepage.html"


@login_required
def profile(request):
    user = request.user
    c = {"username": user.username, "email": user.email}

    return render(request, "profile.html", c)


class NotFoundView(TemplateView):
    template_name = "404.html"


class ErrorView(TemplateView):
    template_name = "500.html"

    @classmethod
    def get_rendered_view(cls):
        as_view_fn = cls.as_view()

        def view_fn(request):
            response = as_view_fn(request)

            response.render()
            return response

        return view_fn


def get_user(request):
    app_tk = request.META["HTTP_AUTHORIZATION"]
    m = re.search(r"(Bearer)(\s)(.*)", app_tk)

    app_tk = m.group(3)

    try:
        payload = decode_jwt_user_info(app_tk)
    except jwt.ExpiredSignatureError:
        msg = "Signature has expired."
        raise exceptions.AuthenticationFailed(msg)
    except jwt.DecodeError:
        msg = "Error decoding signature."
        raise exceptions.AuthenticationFailed(msg)
    except jwt.InvalidTokenError:
        raise exceptions.AuthenticationFailed()
    email = payload["sub"]

    u = get_user_model()
    user = u.objects.get(email=email)

    return HttpResponse(
        json.dumps({"username": user.username, "email": user.email}),
        content_type="application/json",
    )
