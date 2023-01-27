from django.core.files.storage import default_storage
from django.core.management.base import BaseCommand
from django.conf import settings
from elasticsearch import Elasticsearch

es = Elasticsearch([settings.ELASTICSEARCH_HOST], timeout=30, max_retries=5, retry_on_timeout=True)
original_index = settings.ELASTICSEARCH_APK_INDEX
tmp_index = f'{original_index}_tmp'


class Command(BaseCommand):
    help = '''
    Delete the APK that are missing from the Elastic Search index form
    the store. It is for development and bug fixes. You will need to reupload
    your samples after that.
    '''

    def handle(self, *args, **options):
        # Get all APKs from the store

        _, hashes = default_storage.listdir('.')
        for hash in hashes:
            # Check if it exists on the ES:
            if not es.exists(original_index, id=hash):
                default_storage.delete(hash)
