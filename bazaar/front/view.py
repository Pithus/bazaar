from tempfile import NamedTemporaryFile
import logging
from androguard.core.androconf import is_android
from django.conf import settings
from django.contrib import messages
from django.core.cache import cache
from django.core.files.storage import default_storage
from django.http import JsonResponse, HttpResponse
from django.shortcuts import render, redirect
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from django.views.generic import View
from elasticsearch import Elasticsearch
from rest_framework.reverse import reverse_lazy
from bazaar.core.tasks import analyze
from bazaar.core.utils import get_sha256_of_file
from bazaar.front.forms import SearchForm, BasicUploadForm, SimilaritySearchForm
from bazaar.front.utils import transform_results, get_similarity_matrix, compute_status, generate_world_map


@method_decorator(csrf_exempt, name='dispatch')
class HomeView(View):

    def get(self, request, *args, **kwargs):
        # Gets the latest complete report as an example
        es = Elasticsearch(settings.ELASTICSEARCH_HOSTS)
        q = {
            "size": 1,
            "sort": {"analysis_date": "desc"},
            "query": {
                "match_all": {}
            },
            "_source": ["handle", "apk_hash", "quark"]
        }
        report_example = es.search(index=settings.ELASTICSEARCH_APK_INDEX, body=q)
        tmp = transform_results(report_example)
        if tmp:
            report_example = tmp[0]
        else:
            report_example = tmp

        q = None
        matrix = None
        results = None
        list_results = False
        aggregations = []

        f = SearchForm(request.GET)
        form_to_show = f
        if not request.GET:
            form_to_show = SearchForm()
        if f.is_valid():
            results, aggregations = f.do_search()
            list_results = True
            q = f.cleaned_data['q']
            matrix = get_similarity_matrix(results)

        return render(request,
                      'front/index.html',
                      {
                          'form': form_to_show,
                          'results': results,
                          'aggregations': aggregations,
                          'upload_form': BasicUploadForm(),
                          'list_results': list_results,
                          'report_example': report_example,
                          'q': q, 'matrix': matrix,
                          'max_size': settings.MAX_APK_UPLOAD_SIZE
                      })


class ReportView(View):

    def get(self, request, *args, **kwargs):
        if 'sha256' not in kwargs:
            return redirect(reverse_lazy('front:home'))

        sha = kwargs['sha256']
        cache_key = f'html_report_{sha}'

        # First, check if the report is already in cache
        cached_report = cache.get(cache_key)
        if cached_report:
            return cached_report

        # Not cached so, let's compute the report
        es = Elasticsearch(settings.ELASTICSEARCH_HOSTS)
        try:
            result = es.get(index=settings.ELASTICSEARCH_APK_INDEX, id=sha)['_source']
            status = es.get(index=settings.ELASTICSEARCH_TASKS_INDEX, id=sha)['_source']
            status = compute_status(status)

            map_svg = None
            if 'domains_analysis' in result:
                map_svg = generate_world_map(result['domains_analysis'])

            cache_retention_time = 5
            if not status['running']:
                cache_retention_time = 600

            return render(request, 'front/report.html', {
                'result': result,
                'status': status,
                'map': map_svg,
                'cache_retention_time': cache_retention_time})
        except Exception as e:
            logging.exception(e)
            return redirect(reverse_lazy('front:home'))


def basic_upload_view(request):
    if request.method == 'POST':
        form = BasicUploadForm(request.POST, request.FILES)
        if form.is_valid():
            apk = request.FILES['apk']
            if apk.size > settings.MAX_APK_UPLOAD_SIZE:
                messages.warning(request, 'Submitted file is too large.')
                return redirect(reverse_lazy('front:home'))

            with NamedTemporaryFile() as tmp:
                for chunk in apk.chunks():
                    tmp.write(chunk)
                tmp.seek(0)

                if is_android(tmp.name) != 'APK':
                    messages.warning(request, 'Submitted file is not a valid APK.')
                    return redirect(reverse_lazy('front:home'))

                sha256 = get_sha256_of_file(tmp)
                if default_storage.exists(sha256):
                    # analyze(sha256, force=True)
                    return redirect(reverse_lazy('front:report', [sha256]))
                else:
                    default_storage.save(sha256, tmp)
                    analyze(sha256)
                    return redirect(reverse_lazy('front:report', [sha256]))

    return redirect(reverse_lazy('front:home'))


def similarity_search_view(request):
    if request.method == 'GET':
        form = SimilaritySearchForm(request.GET)
        results = None
        if form.is_valid():
            results = form.do_search()
        return render(request, 'front/similarity_search.html', {'form': form, 'results': results})


def download_sample_view(request, sha256):
    if not request.user.is_authenticated:
        return redirect(reverse_lazy('front:home'))

    if request.method == 'GET':
        if not default_storage.exists(sha256):
            return redirect(reverse_lazy('front:home'))

        response = HttpResponse(default_storage.open(sha256).read(), content_type="application/vnd.android.package-archive")
        response['Content-Disposition'] = f'inline; filename=pithus_sample_{sha256}.apk'
        return response

def export_report_view(request, sha256):
    if not request.user.is_authenticated:
        return redirect(reverse_lazy('front:home'))

    if request.method == 'GET':
        es = Elasticsearch(settings.ELASTICSEARCH_HOSTS)
        try:
            result = es.get(index=settings.ELASTICSEARCH_APK_INDEX, id=sha256)['_source']
            response = JsonResponse(result)
            response['Content-Disposition'] = f'attachment; filename=pithus_report_{sha256}.json'
            return response
        except Exception as e:
            logging.exception(e)
            return redirect(reverse_lazy('front:home'))

