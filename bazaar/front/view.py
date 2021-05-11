import logging
from tempfile import NamedTemporaryFile

from androguard.core.androconf import is_android
from django.conf import settings
from django.contrib import messages
from django.core.cache import cache
from django.core.files.storage import default_storage
from django.http import JsonResponse, HttpResponse
from django.http.response import HttpResponseBadRequest
from django.shortcuts import render, redirect
from django.utils import timezone
from django.utils.decorators import method_decorator
from django.views.decorators.cache import cache_page
from django.views.decorators.csrf import csrf_exempt
from django.views.generic import View
from elasticsearch import Elasticsearch
from rest_framework.reverse import reverse_lazy

from django_q.tasks import async_task

from bazaar.core.models import Yara
from bazaar.core.tasks import analyze, retrohunt
from bazaar.core.utils import get_sha256_of_file, get_matching_items_by_dexofuzzy
from bazaar.front.forms import SearchForm, BasicUploadForm, SimilaritySearchForm
from bazaar.front.og import generate_og_card
from bazaar.front.utils import transform_results, get_similarity_matrix, compute_status, generate_world_map, \
    transform_hl_results
from .forms import YaraCreateForm


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

            # Generate map
            map_svg = None
            if 'domains_analysis' in result:
                map_svg = generate_world_map(result['domains_analysis'])

            # Find similar sample based on dexofuzzy
            similar_samples = None
            try:
                dexofuzzy_hash = result['dexofuzzy']['apk']
                if dexofuzzy_hash:
                    similar_samples = get_matching_items_by_dexofuzzy(
                        dexofuzzy_hash,
                        25,
                        settings.ELASTICSEARCH_DEXOFUZZY_APK_INDEX, '')
            except Exception:
                pass

            # Find public hunting results
            hunting_matches = Yara.find_public_hunting_matches(sha)

            # Adapt caching depending on the status of the analysis
            cache_retention_time = 5
            if not status['running']:
                cache_retention_time = 600

            return render(request, 'front/report.html', {
                'result': result,
                'status': status,
                'map': map_svg,
                'hunting_matches': hunting_matches,
                'similar_samples': similar_samples,
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

        response = HttpResponse(default_storage.open(sha256).read(),
                                content_type="application/vnd.android.package-archive")
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


@cache_page(2 * 60 * 60)
def og_card_view(request, sha256):
    if request.method == 'GET':
        with NamedTemporaryFile() as fp:
            generate_og_card(sha256, fp.name)
            return HttpResponse(fp.read(), content_type="image/png")


def my_rules_view(request):
    if not request.user.is_authenticated:
        return redirect(reverse_lazy('front:home'))

    my_rules = None
    if request.method == 'GET':
        my_rules = get_rules(request)

    return render(request, 'front/yara_rules/my_rules.html', context={'my_rules': my_rules})


def my_rule_create_view(request):
    if not request.user.is_authenticated:
        return redirect(reverse_lazy('front:home'))

    new_rule = YaraCreateForm()

    if request.method == 'POST':
        new_rule = YaraCreateForm(request.POST)
        try:
            new_rule = new_rule.save(commit=False)
            new_rule.owner = request.user
            new_rule.last_update = timezone.now()
            new_rule.save()
            messages.success(request, 'Your rule has been created!')
        except Exception:
            return render(request, 'front/yara_rules/my_rule_edit.html', {'form': new_rule})
        return redirect(reverse_lazy('front:my_rules'))

    return render(request, 'front/yara_rules/my_rule_edit.html', {'form': new_rule})


def my_rule_edit_view(request, uuid):
    if not request.user.is_authenticated:
        return redirect(reverse_lazy('front:home'))

    if request.method == 'GET':
        rule = Yara.objects.get(id=uuid)
        new_rule = YaraCreateForm(instance=rule)
        return render(request, 'front/yara_rules/my_rule_edit.html', {'form': new_rule, 'edit': True})

    elif request.method == 'POST':
        rule = Yara.objects.get(id=uuid)
        new_rule = YaraCreateForm(request.POST or None, instance=rule)
        try:
            new_rule = new_rule.save(commit=False)
            new_rule.owner = request.user
            new_rule.last_update = timezone.now()
            new_rule.save()
            delete_es_matches(request, rule)
            messages.success(request, 'Your rule has been updated!')
        except Exception:
            return render(request, 'front/yara_rules/my_rule_edit.html', {'form': new_rule})
        return redirect(reverse_lazy('front:my_rules'))
    else:
        return HttpResponseBadRequest()


def my_rule_delete_view(request, uuid=None):
    if not request.user.is_authenticated:
        return redirect(reverse_lazy('front:home'))

    if request.method == 'GET':
        rule = Yara.objects.get(id=uuid)
        try:
            delete_es_matches(request, rule)
            rule.delete()
            messages.success(request, 'Your rule has been deleted.')
            return redirect(reverse_lazy('front:my_rules'))
        except Exception as e:
            logging.exception(e)
            return redirect(reverse_lazy('front:my_rules'))


def delete_es_matches(request, rule):
    es = Elasticsearch(settings.ELASTICSEARCH_HOSTS)
    public_es_index, private_es_index = Yara.get_es_index_names(request.user)
    q = {'query': {
        'match': {
            'rule': rule.id,
        }
    }}
    if rule.is_private:
        try:
            es.delete_by_query(index=private_es_index, body=q)
        except Exception as e:
            logging.exception(e)
    elif not rule.is_private:
        try:
            es.delete_by_query(index=public_es_index, body=q)
        except Exception as e:
            logging.exception(e)
    else:
        pass

    return


def get_rules(request):
    es = Elasticsearch(settings.ELASTICSEARCH_HOSTS)
    yara_rules = Yara.objects.filter(owner=request.user)
    public_es_index, private_es_index = Yara.get_es_index_names(request.user)
    q = {
        'query': {
            'terms': {
                'owner': [request.user.id]
            }
        },
        'size': 5000,
    }

    public_matches, private_matches = None, None
    try:
        private_matches = es.search(index=private_es_index, body=q)['hits']['hits']
    except:
        pass

    try:
        public_matches = es.search(index=public_es_index, body=q)['hits']['hits']
    except:
        pass

    my_rules = []
    for rule in yara_rules:
        my_rule = {
            'rule': rule,
            'matching_date': '',
            'matches': [],
        }
        if rule.is_private and private_matches:
            for match in private_matches:
                if match['_source']['rule'] == str(rule.id):
                    m = match['_source']
                    m['sample'] = get_sample_light(match['_source']['matches']['apk_id'])
                    my_rule['matches'].append(m)
        elif not rule.is_private and public_matches:
            for match in public_matches:
                if match['_source']['rule'] == str(rule.id):
                    m = match['_source']
                    m['sample'] = get_sample_light(match['_source']['matches']['apk_id'])
                    my_rule['matches'].append(m)
        my_rules.append(my_rule)

    return my_rules


def get_sample_light(sha256):
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
    es = Elasticsearch(settings.ELASTICSEARCH_HOSTS)
    try:
        results = es.search(index=settings.ELASTICSEARCH_APK_INDEX, body=query)
        results = transform_hl_results(results)
        return results
    except Exception:
        return []


def my_retrohunt_view(request, uuid):
    # TODO: add a cap on user use
    try:
        async_task(retrohunt, uuid)
        messages.success(request, 'The retrohunt has been launched.')
    except Exception as e:
        logging.exception(e)

    return redirect(reverse_lazy('front:my_rules'))
