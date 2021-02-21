from typing import Any

from allauth.account.adapter import DefaultAccountAdapter
from allauth.socialaccount.adapter import DefaultSocialAccountAdapter
from django.conf import settings
from django.http import HttpRequest


class AccountAdapter(DefaultAccountAdapter):
    def is_open_for_signup(self, request: HttpRequest):
        return getattr(settings, "ACCOUNT_ALLOW_REGISTRATION", True)


class SocialAccountAdapter(DefaultSocialAccountAdapter):
    def is_open_for_signup(self, request: HttpRequest):
        return getattr(settings, "ACCOUNT_ALLOW_REGISTRATION", True)

    def is_safe_url(self, url):
        try:
            from django.utils.http import url_has_allowed_host_and_scheme
        except ImportError:
            from django.utils.http import (
                is_safe_url as url_has_allowed_host_and_scheme,
            )

        return url_has_allowed_host_and_scheme(url, allowed_hosts=None)

    def is_ajax(self, request):
        return any(
            [
                request.META.get("HTTP_X_REQUESTED_WITH") == "XMLHttpRequest",
                request.content_type == "application/json",
                request.META.get("HTTP_ACCEPT") == "application/json",
            ]
        )
