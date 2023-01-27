# Automatically create superuser
import os
import secrets

from django.db import migrations
from django.utils import timezone
from django.contrib.auth import get_user_model


def create_superuser(apps, schema_editor):
    if 'DJANGO_SUPERUSER_USERNAME' not in os.environ:
        return

    superuser = get_user_model()(
        is_active=True,
        is_superuser=True,
        is_staff=True,
        username=os.environ['DJANGO_SUPERUSER_USERNAME'],
        email=os.environ['DJANGO_SUPERUSER_EMAIL'],
        last_login=timezone.now(),

    )
    os.environ['DJANGO_SUPERUSER_PASSWORD'] = secrets.token_hex(16)
    superuser.set_password(os.environ['DJANGO_SUPERUSER_PASSWORD'])
    superuser.save()
    print('\ndjango username:%s\n' % os.environ['DJANGO_SUPERUSER_USERNAME'])
    print('\ndjango password:%s\n' % os.environ['DJANGO_SUPERUSER_PASSWORD'])






class Migration(migrations.Migration):

    dependencies = [
        ('core', '0004_auto_20210305_1346'),
    ]

    operations = [migrations.RunPython(create_superuser)]
