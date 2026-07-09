import logging
import json

from django.conf import settings
from elasticsearch import Elasticsearch
from bazaar.core.utils import   get_matching_items_by_dexofuzzy, \
                                get_matching_items_by_ssdeep, \
                                get_matching_items_by_ssdeep_func, \
                                transform_hl_results


def search(search_query):
    query = {
        "query": {
            "query_string": {
                "default_field": "sha256",
                "query": search_query,
            }
        },
        "highlight": {
            "fields": {
                "*": {"pre_tags": ["<mark>"], "post_tags": ["</mark>"]}
            }
        },
        "aggs": {
            "permissions": {
                "terms": {"field": "permissions.keyword"}
            },
            "domains": {
                "terms": {"field": "domains_analysis._name.keyword"}
            },
            "android_features": {
                "terms": {"field": "features.keyword"}
            }
        },
        "sort": {"analysis_date": "desc"},
        "_source": ["apk_hash", "sha256", "uploaded_at", "icon_base64", "handle", "app_name",
                    "version_code", "size", "dexofuzzy.apk", "quark.threat_level", "vt", "vt_report", "malware_bazaar",
                    "is_signed", "frosting_data.is_frosted", "features", "andro_cfg"],
        "size": 50,
    }
    es = Elasticsearch(settings.ELASTICSEARCH_HOSTS, basic_auth=(settings.ELASTICSEARCH_USER, settings.ELASTICSEARCH_PASSWORD))
    try:
        results = es.search(index=settings.ELASTICSEARCH_APK_INDEX, body=query)
        return results
    except Exception:
        return []

def light_sample_search(sha256):
    query = {
        "query": {
            "match": {
                "apk_hash": sha256
            }
        },
        "_source": ["apk_hash", "sha256", "uploaded_at", "icon_base64", "handle", "app_name",
                    "version_code", "size", "dexofuzzy.apk", "quark.threat_level", "vt", "malware_bazaar",
                    "is_signed", "frosting_data.is_frosted", "features"],
        "size": 1,
    }
    es = Elasticsearch(settings.ELASTICSEARCH_HOSTS, basic_auth=(settings.ELASTICSEARCH_USER, settings.ELASTICSEARCH_PASSWORD))
    try:
        results = es.search(index=settings.ELASTICSEARCH_APK_INDEX, body=query)
        results = transform_hl_results(results)
        return results
    except Exception:
        return []

def similarity_search(search_hash, algorithm, ignore_sha=''):
    results = []
    try:
        match algorithm:
            case 'dexofuzzy':
                results = get_matching_items_by_dexofuzzy(
                    search_hash, 25, settings.ELASTICSEARCH_DEXOFUZZY_APK_INDEX, ignore_sha
                )
            case 'ssdeep':
                results = get_matching_items_by_ssdeep(
                    search_hash, 25, settings.ELASTICSEARCH_SSDEEP_APK_INDEX, ignore_sha
                )
            case 'func_hash':
                results = get_matching_items_by_ssdeep_func(
                    search_hash, 25, settings.ELASTICSEARCH_APK_INDEX, ignore_sha
                )
    except Exception as e:
        logging.error(e)

    return results
