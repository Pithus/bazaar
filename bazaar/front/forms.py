from django import forms
from django.conf import settings
from elasticsearch import Elasticsearch

from bazaar.front.utils import transform_results, transform_hl_results, append_dexofuzzy_similarity, get_aggregations


class BasicSearchForm(forms.Form):
    q = forms.CharField(label='The SHA256 you are looking for', max_length=65)

    def do_search(self):
        q = self.cleaned_data['q']
        query = {
            "query": {
                "match": {
                    "apk_hash": q.lower()
                }
            },
            "_source": ["handle", "apk_hash", "size", "app_name"],
            "size": 50,
        }
        es = Elasticsearch([settings.ELASTICSEARCH_HOST])
        try:
            results = es.search(index=settings.ELASTICSEARCH_APK_INDEX, body=query)
            results = transform_results(results)
            return results
        except Exception:
            return []


class SearchForm(forms.Form):
    q = forms.CharField(max_length=128)

    def do_search(self):
        mapping = {
            'cert_md5': 'certificates.fingerprint_md5',
            'cert_sha1': 'certificates.fingerprint_sha1',
            'cert_sha256': 'certificates.fingerprint_sha256',
            'tracker': 'trackers.name',
            'domains': 'domains_analysis._name',
            'features': 'features',
            'cert_issuer': 'certificates.issuer',
        }
        q = self.cleaned_data['q']

        for k, v in mapping.items():
            if k in q:
                q = q.replace(k, v)

        query = {
            "query": {
                "query_string": {
                    "default_field": "sha256",
                    "query": q
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
                "android_api": {
                    "terms": {"field": "android_api_analysis.metadata.description.keyword"}
                },
                "android_features": {
                    "terms": {"field": "features.keyword"}
                }
            },
            "_source": ["apk_hash", "sha256", "handle", "app_name", "dexofuzzy.apk"],
            "size": 50,
        }
        es = Elasticsearch([settings.ELASTICSEARCH_HOST])
        try:
            raw_results = es.search(index=settings.ELASTICSEARCH_APK_INDEX, body=query)
            results = transform_hl_results(raw_results)
            results = append_dexofuzzy_similarity(results, 'sim', 30)
            return results, get_aggregations(raw_results)
        except Exception as e:
            raise e
            return [], []


class BasicUploadForm(forms.Form):
    apk = forms.FileField()
