from django.db.models.signals import post_save
from django.dispatch import receiver
from django.conf import settings as django_settings

from .models import Settings


@receiver(post_save, sender=django_settings.AUTH_USER_MODEL)
def create_user_settings(sender, instance, created, **kwargs):
    if created:
        Settings.objects.get_or_create(user=instance)
