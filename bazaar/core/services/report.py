
from django.conf import settings
from elasticsearch import Elasticsearch

from bazaar.core.utils import compute_status


def list_reports() -> []:
    try:
        es = Elasticsearch(
            settings.ELASTICSEARCH_HOSTS,
            basic_auth=(settings.ELASTICSEARCH_USER, settings.ELASTICSEARCH_PASSWORD)
        )
        q = {
            "sort": {"analysis_date": "desc"},
            "query": {
                "match_all": {}
            },
            "_source": ["handle", "apk_hash"]
        }
        reports = []
        for report in es.search(index=settings.ELASTICSEARCH_APK_INDEX, body=q)["hits"]["hits"]:
            reports.append(report["_source"])
    except Exception:
        raise
    return reports


def get_report(sha256) -> {}:
    try:
        es = Elasticsearch(
            settings.ELASTICSEARCH_HOSTS,
            basic_auth=(settings.ELASTICSEARCH_USER, settings.ELASTICSEARCH_PASSWORD)
        )
        report = es.get(index=settings.ELASTICSEARCH_APK_INDEX, id=sha256)['_source']
    except Exception:
        raise
    return report


def get_detailed_status(sha256):
    try:
        es = Elasticsearch(
            settings.ELASTICSEARCH_HOSTS,
            basic_auth=(settings.ELASTICSEARCH_USER, settings.ELASTICSEARCH_PASSWORD)
        )
        detailed_status = es.get(index=settings.ELASTICSEARCH_TASKS_INDEX, id=sha256)['_source']
    except Exception:
        raise
    return detailed_status


def get_status(sha256) -> {}:
    try:
        detailed_status = get_detailed_status(sha256)
        report_status = compute_status(detailed_status)
    except Exception:
        raise
    return report_status


def get_example() -> {}:
    try:
        es = Elasticsearch(
            settings.ELASTICSEARCH_HOSTS,
            basic_auth=(settings.ELASTICSEARCH_USER, settings.ELASTICSEARCH_PASSWORD)
        )
        q = {
            "size": 1,
            "sort": {"analysis_date": "desc"},
            "query": {
                "match_all": {}
            },
        }
        example = es.search(index=settings.ELASTICSEARCH_APK_INDEX, body=q)['hits']['hits'][0]['_source']
    except Exception:
        return None
    return example
