from django import forms
from django.conf import settings
from elasticsearch import Elasticsearch

from bazaar.front.utils import transform_results


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
            "_source": ["handle", "apk_hash", "size", "app_name"]
        }
        es = Elasticsearch([settings.ELASTICSEARCH_HOST])
        try:
            results = es.search(index=settings.ELASTICSEARCH_APK_INDEX, body=query)
            return transform_results(results)
        except Exception:
            return []


class BasicUploadForm(forms.Form):
    apk = forms.FileField()
