import gc
import logging

from django.conf import settings
from django.core.files.storage import default_storage
from django.utils import timezone
from django_q.tasks import async_task
from elasticsearch import Elasticsearch

from bazaar.core.modules import (
    androcfg,
    apkid,
    malware_bazaar,
    mobsf,
    pithus,
    quarkengine,
    similarity,
    virus_total,
)


es = Elasticsearch(
    settings.ELASTICSEARCH_HOSTS,
    request_timeout=30, max_retries=5,
    retry_on_timeout=True,
    basic_auth=(settings.ELASTICSEARCH_USER, settings.ELASTICSEARCH_PASSWORD)
)


def _prepare(sha256):
    tasks = {
        'apkid_analysis': 0,
        'ssdeep_analysis': 0,
        'extract_classes': 0,
        'quark_analysis': 0,
        'analysis_date': timezone.now()
    }

    if not es.exists(index=settings.ELASTICSEARCH_TASKS_INDEX, id=sha256):
        es.index(index=settings.ELASTICSEARCH_TASKS_INDEX, id=sha256, body=tasks)
    else:
        es.update(index=settings.ELASTICSEARCH_TASKS_INDEX, id=sha256, body={'doc': tasks}, retry_on_conflict=5)


def analyze(sha256, force=False):
    if not default_storage.exists(sha256):
        reason = f'{sha256} not found, unable to analyze'
        logging.error(reason)
        return {'status': 'error', 'info': reason}

    if es.exists(index=settings.ELASTICSEARCH_APK_INDEX, id=sha256) and not force:
        return {'status': 'success', 'info': ''}

    # Schedule all other tasks
    package = pithus.extract_attributes(sha256)
    if package:
        _prepare(sha256)
        async_task(mobsf.analysis, sha256)
        async_task(malware_bazaar.analysis, sha256)
        async_task(virus_total.analysis, sha256)
        async_task(apkid.analysis, sha256)
        async_task(similarity.analysis, sha256)
        async_task(androcfg.analysis, sha256)
        async_task(quarkengine.analysis, sha256)
        async_task(pithus.yara_analysis, sha256)
        async_task(pithus.get_google_play_info, package)
        async_task(pithus.frosting_analysis, sha256)
        async_task(pithus.extract_classes, sha256)

    gc.collect()

    return {'status': 'success', 'info': ''}
