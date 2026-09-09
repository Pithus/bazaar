
import vt
from django.conf import settings

from elasticsearch import Elasticsearch


es = Elasticsearch(
    settings.ELASTICSEARCH_HOSTS,
    basic_auth=(settings.ELASTICSEARCH_USER, settings.ELASTICSEARCH_PASSWORD)
)


def analysis(sha256):
    try:
        es.update(
            index=settings.ELASTICSEARCH_TASKS_INDEX, id=sha256, body={'doc': {'vt_analysis': 1}},
            retry_on_conflict=5
        )
        client = vt.Client(settings.VT_API_KEY)
        file = client.get_json(f'/files/{sha256}')['data']
        if file['attributes']['last_analysis_stats']:
            d = file['attributes']['last_analysis_stats']
            total = d['undetected'] + d['malicious']
            d['total'] = total
            es.update(
                index=settings.ELASTICSEARCH_APK_INDEX, id=sha256, body={'doc': {'vt': d, 'vt_report': file}},
                retry_on_conflict=5
            )
        es.update(
            index=settings.ELASTICSEARCH_TASKS_INDEX, id=sha256, body={'doc': {'vt_analysis': 2}},
            retry_on_conflict=5
        )
    except Exception:
        es.update(
            index=settings.ELASTICSEARCH_TASKS_INDEX, id=sha256, body={'doc': {'vt_analysis': -1}},
            retry_on_conflict=5
        )
        return
