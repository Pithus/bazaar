import json
from datetime import timedelta

from django.core.management.base import BaseCommand
from django.urls import reverse
from django_q.models import Schedule
from django_q.tasks import schedule

from bazaar.core.tasks import *
from bazaar.core.utils import upload_sample_to_malware_bazaar


class Command(BaseCommand):
    help = 'Upload malwares to MalwareBazaar'

    def add_arguments(self, parser):
        parser.add_argument('hash', type=str)

    def handle(self, *args, **options):
        sha256 = options['hash']

        if '*' in sha256:
            _, hashes = default_storage.listdir('.')
            for h in hashes:
                self._handle_sample(h)

    def _handle_sample(self, sha256):
        upload_sample_to_malware_bazaar(sha256)
