from tempfile import NamedTemporaryFile

from django.conf import settings
from django.contrib import messages
from django.core.files.storage import default_storage
from django.shortcuts import render, redirect
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from django.views.generic import View
from elasticsearch import Elasticsearch
from rest_framework.reverse import reverse_lazy

from bazaar.core.tasks import analyze
from bazaar.core.utils import get_sha256_of_file
from bazaar.front.forms import BasicSearchForm, BasicUploadForm
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

        return render(request, 'front/index.html',
                      {'form': form_to_show, 'results': results, 'upload_form': BasicUploadForm()})


class ReportView(View):

    def get(self, request, *args, **kwargs):
        if 'sha256' not in kwargs:
            return redirect(reverse_lazy('front:home'))
        sha = kwargs['sha256']
        es = Elasticsearch([settings.ELASTICSEARCH_HOST])
        try:
            result = es.get(index=settings.ELASTICSEARCH_APK_INDEX, id=sha)['_source']
            if 'analysis_date' not in result or 'apkid' not in result:
                messages.info(request, 'The analysis is still running, refresh this page in few minutes.')
        except Exception:
            return redirect(reverse_lazy('front:home'))

        return render(request, 'front/report.html', {'result': result})


def basic_upload_view(request):
    if request.method == 'POST':
        form = BasicUploadForm(request.POST, request.FILES)
        if form.is_valid():
            apk = request.FILES['apk']
            with NamedTemporaryFile() as tmp:
                for chunk in apk.chunks():
                    tmp.write(chunk)
                tmp.seek(0)
                sha256 = get_sha256_of_file(tmp)
                if default_storage.exists(sha256):
                    return redirect(reverse_lazy('front:report', [sha256]))
                else:
                    default_storage.save(sha256, tmp)
                    analyze(sha256)
                    return redirect(reverse_lazy('front:report', [sha256]))

    return redirect(reverse_lazy('front:home'))
