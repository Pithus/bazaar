from elasticsearch import Elasticsearch

from django.conf import settings
from django.core.management.base import BaseCommand
from django.core.files.storage import default_storage


indexes = [
    'apk_analysis',
    'apk_analysis_tmp',
    'analysis_tasks',
    'vt_reports',
    'google_play_details',
    'dexofuzzy_apk',
    'ssdeep_apk',
    'ssdeep_manifest',
]
es = Elasticsearch(
    settings.ELASTICSEARCH_HOSTS,
    basic_auth=(settings.ELASTICSEARCH_USER, settings.ELASTICSEARCH_PASSWORD)
)


class Command(BaseCommand):
    help = 'Remove an APK and its report data'

    def add_arguments(self, parser):
        parser.add_argument('hash', type=str)

    def handle(self, *args, **options):
        sha256 = options['hash']

        if default_storage.exists(sha256):
            print("APK is saved to default_storage, removing…")
            default_storage.delete(sha256)
        if default_storage.exists(f"andro_cfg_{sha256}"):
            print("AndroCFG data saved to default_storage, removing…")
            default_storage.delete(f"andro_cfg_{sha256}")

        for i in indexes:
            try:
                es.delete(index=i, id=sha256)
            except Exception:
                pass
