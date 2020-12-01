from django.conf import settings
from django.shortcuts import render, redirect
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from django.views.generic import View
from elasticsearch import Elasticsearch
from rest_framework.reverse import reverse_lazy

from bazaar.front.forms import BasicSearchForm
from bazaar.front.utils import transform_results


@method_decorator(csrf_exempt, name='dispatch')
class HomeView(View):

    def get(self, request, *args, **kwargs):
        query = {
            "query": {
                "match_all": {}
            },
            "_source": ["handle", "apk_hash", "size", "app_name"]
        }
        f = BasicSearchForm(request.GET)
        form_to_show = f
        if not request.GET:
            form_to_show = BasicSearchForm()
        if f.is_valid():
            results = f.do_search()
        else:
            es = Elasticsearch([settings.ELASTICSEARCH_HOST])
            results = es.search(index=settings.ELASTICSEARCH_APK_INDEX, body=query)
            results = transform_results(results)

        return render(request, 'front/index.html', {'form': form_to_show, 'results': results})


class ReportView(View):

    def get(self, request, *args, **kwargs):
        if 'sha256' not in kwargs:
            return redirect(reverse_lazy('front:home'))
        sha = kwargs['sha256']
        query = {
            "query": {
                "match": {
                    "apk_hash": sha.lower()
                }
            },
            "_source": {
                "exclude": ["external_classes", "secrets", "playstore_details.description"]
            }
        }
        es = Elasticsearch([settings.ELASTICSEARCH_HOST])
        try:
            result = es.get(index=settings.ELASTICSEARCH_APK_INDEX, id=sha)['_source']
        except:
            return redirect(reverse_lazy('front:home'))

        return render(request, 'front/report.html', {'result': result})
