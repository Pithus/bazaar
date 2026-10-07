from django.conf import settings
from bazaar.core.models import Notification


def settings_context(_request):
    """Settings available by default to the templates context."""
    # Note: we intentionally do NOT expose the entire settings
    # to prevent accidental leaking of sensitive information
    return {"DEBUG": settings.DEBUG}


def notifications(request):
    if not request.user.is_authenticated:
        return {"has_notifications": False}

    return {
        "has_notifications": Notification.objects.filter(
            user=request.user,
        ).exists()
    }
