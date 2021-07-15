from django import forms
from django.conf import settings
from elasticsearch import Elasticsearch

from bazaar.core.utils import get_matching_items_by_dexofuzzy, get_matching_items_by_ssdeep, compute_genetic_analysis
from bazaar.front.utils import transform_results, transform_hl_results, append_dexofuzzy_similarity, get_aggregations

from django.forms import ModelForm
from bazaar.core.models import Yara


class BasicSearchForm(forms.Form):
    q = forms.CharField(label='The SHA256 you are looking for', max_length=65)

    def do_search(self):
        q = self.cleaned_data['q']
        query = {
            "sort": {"analysis_date": "desc"},
            "query": {
                "match": {
                    "apk_hash": q.lower()
                }
            },
            "_source": ["handle", "apk_hash", "size", "app_name"],
            "size": 50,
        }
        es = Elasticsearch(settings.ELASTICSEARCH_HOSTS)
        try:
            results = es.search(index=settings.ELASTICSEARCH_APK_INDEX, body=query)
            results = transform_results(results)
            return results
        except Exception:
            return []


class SimilaritySearchForm(forms.Form):
    hash = forms.CharField(max_length=128)
    algorithm = forms.ChoiceField(choices=[('ssdeep', 'ssdeep'), ('dexofuzzy', 'dexofuzzy')])

    def do_search(self):
        print(self.cleaned_data)
        results = []
        algorithm = self.cleaned_data['algorithm']
        hash = self.cleaned_data['hash'].strip()
        try:
            if algorithm == 'dexofuzzy':
                results = get_matching_items_by_dexofuzzy(hash, 25, settings.ELASTICSEARCH_DEXOFUZZY_APK_INDEX, '')
            if algorithm == 'ssdeep':
                results = get_matching_items_by_ssdeep(hash, 25, settings.ELASTICSEARCH_SSDEEP_APK_INDEX, '')

        except Exception as e:
            print(e)

        return results


class SearchForm(forms.Form):
    q = forms.CharField(max_length=128)

    def do_search(self):
        q = self.cleaned_data['q']

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
                "android_features": {
                    "terms": {"field": "features.keyword"}
                }
            },
            "sort": {"analysis_date": "desc"},
            "_source": ["apk_hash", "sha256", "uploaded_at", "icon_base64", "handle", "app_name",
                        "version_code", "size", "dexofuzzy.apk", "quark.threat_level", "vt", "vt_report", "malware_bazaar",
                        "is_signed", "frosting_data.is_frosted", "features", "andro_cfg.genom"],
            "size": 50,
        }
        es = Elasticsearch(settings.ELASTICSEARCH_HOSTS)
        try:
            raw_results = es.search(index=settings.ELASTICSEARCH_APK_INDEX, body=query)
            results = transform_hl_results(raw_results)
            results = append_dexofuzzy_similarity(results, 'sim', 30)
            genetic_analysis = compute_genetic_analysis(results)
            return results, get_aggregations(raw_results), genetic_analysis
        except Exception as e:
            return [], [], None


class BasicUploadForm(forms.Form):
    apk = forms.FileField()


class YaraCreateForm(ModelForm):
    class Meta:
        model = Yara
        fields = ['title', 'content', 'is_private']
