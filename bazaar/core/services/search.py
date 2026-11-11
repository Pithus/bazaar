import logging

from django.conf import settings
from elasticsearch import Elasticsearch
from bazaar.core.utils import get_matching_items_by_dexofuzzy, \
    get_matching_items_by_ssdeep, \
    get_matching_items_by_ssdeep_func, \
    get_matching_items_by_tlsh, \
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
    es = Elasticsearch(
        settings.ELASTICSEARCH_HOSTS,
        basic_auth=(settings.ELASTICSEARCH_USER, settings.ELASTICSEARCH_PASSWORD)
    )
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
    es = Elasticsearch(
        settings.ELASTICSEARCH_HOSTS,
        basic_auth=(settings.ELASTICSEARCH_USER, settings.ELASTICSEARCH_PASSWORD)
    )
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
                    search_hash, 25, settings.ELASTICSEARCH_APK_INDEX
                )
            case 'tlsh':
                results = get_matching_items_by_tlsh(
                    search_hash, 100, settings.ELASTICSEARCH_APK_INDEX, ignore_sha
                )
    except Exception as e:
        logging.error(e)

    return results


def compare_search(left_sha, right_sha):
    shas = []
    shas.append(left_sha)
    shas.append(right_sha)

    results = []
    for sha in shas:
        query = {
            "query": {
                "query_string": {
                    "default_field": "sha256",
                    "query": sha,
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
            "_source": [
                "uaid",
                "signatures",
                "is_signed",
                "is_signed_v1",
                "is_signed_v2",
                "is_signed_v3",
                "certificates",
                "dexofuzzy",
                "apkid",
                "manifest_analysis",
                "browsable_activities",
                "niap_analysis",
                "code_analysis",
                "detailed_permissions",
                "trackers",
                "quark.crimes",
                "android_api_analysis",
                "ssdeep",
                "version_name",
                "apk_hash",
                "app_name",
                "dexofuzzy.apk",
                "features"
                "frosting_data.is_frosted",
                "handle",
                "is_signed",
                "md5",
                "quark.threat_level",
                "sha1",
                "sha256",
                "size",
                "uploaded_at",
                "version_code",
            ],
            "size": 1,
        }
        es = Elasticsearch(settings.ELASTICSEARCH_HOSTS)
        try:
            raw_results = es.search(index=settings.ELASTICSEARCH_APK_INDEX, body=query)
            results.append(transform_hl_results(raw_results))
        except Exception:
            return []

    return results
