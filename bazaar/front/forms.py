import logging
from django import forms

from bazaar.core.services import SearchService
from bazaar.core.utils import compute_genetic_analysis, transform_hl_results
from bazaar.front.utils import append_dexofuzzy_similarity, get_aggregations

from django.forms import ModelForm
from bazaar.core.models import Yara
from bazaar.core.models import Comment


class SimilaritySearchForm(forms.Form):
    hash = forms.CharField(max_length=128)
    algorithm = forms.ChoiceField(
        choices=[('ssdeep', 'ssdeep'), ('dexofuzzy', 'dexofuzzy'), ('func_hash', 'func_hash')])

    def do_search(self, sha=''):
        algorithm = self.cleaned_data['algorithm']
        hash = self.cleaned_data['hash'].strip()

        return SearchService.similarity_search(hash, algorithm, ignore_sha=sha)


class SearchForm(forms.Form):
    q = forms.CharField(max_length=128)

    def do_search(self):
        q = self.cleaned_data['q']

        try:
            raw_results = SearchService.search(q)
            results = transform_hl_results(raw_results)
            results = append_dexofuzzy_similarity(results, 'sim', 30)

            genetic_analysis = compute_genetic_analysis(results)
            return results, get_aggregations(raw_results), genetic_analysis
        except Exception as e:
            logging.error(e)
            return [], [], None


class BasicUploadForm(forms.Form):
    apk = forms.FileField()


class BasicUrlDownloadForm(forms.Form):
    url = forms.URLField()


class YaraCreateForm(ModelForm):
    class Meta:
        model = Yara
        fields = ['title', 'content', 'is_private']


class CommentForm(forms.ModelForm):
    class Meta:
        model = Comment
        fields = ["content"]
        widgets = {
            "content": forms.Textarea(attrs={
                "rows": 5,
            }),
        }


class CompareSearchForm(forms.Form):
    left_sha = forms.CharField()
    right_sha = forms.CharField()

    def do_search(self):
        shas = []
        shas.append(self['left_sha'].value())
        shas.append(self['right_sha'].value())

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
            except Exception as e:
                return []

        return results
