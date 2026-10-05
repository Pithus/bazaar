import logging
from tempfile import NamedTemporaryFile

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
from django_q.tasks import async_task

from rest_framework.authtoken.models import Token
from rest_framework.reverse import reverse_lazy
from pygments import highlight
from pygments.formatters import HtmlFormatter
from pygments.lexers.jvm import JavaLexer
from androcfg.code_style import U39bStyle

from bazaar.core.services import ReportService
from bazaar.core.services import ApkService
from bazaar.core.services import SearchService
from bazaar.core.services import RulesService
from bazaar.core.services import GenomService

from bazaar.core.models import Yara
from bazaar.core.modules.pithus import retrohunt
from bazaar.core.utils import get_matching_items_by_dexofuzzy
from bazaar.front.forms import SearchForm, BasicUploadForm, SimilaritySearchForm, BasicUrlDownloadForm
from bazaar.front.og import generate_og_card
from bazaar.front.utils import get_similarity_matrix, generate_world_map, \
    get_sample_timeline, get_andro_cfg_storage_path
from .forms import YaraCreateForm


@method_decorator(csrf_exempt, name='dispatch')
class HomeView(View):

    def get(self, request, *args, **kwargs):

        report_example = ReportService.get_example()
        q = None
        matrix = None
        results = None
        list_results = False
        aggregations = []
        genetic_analysis = None

        f = SearchForm(request.GET)
        form_to_show = f
        if not request.GET:
            form_to_show = SearchForm()
        if f.is_valid():
            results, aggregations, genetic_analysis = f.do_search()
            list_results = True
            q = f.cleaned_data['q']
            matrix = get_similarity_matrix(results)

        return render(request,
                      'front/index.html',
                      {
                          'form': form_to_show,
                          'results': results,
                          'aggregations': aggregations,
                          'genetic_analysis': genetic_analysis,
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
        if request.user.is_authenticated:
            cache_key = f'html_report_{sha}_authenticated'

        # First, check if the report is already in cache
        cached_report = cache.get(cache_key)
        if cached_report:
            return cached_report

        # Not cached so, let's compute the report
        try:
            result = ReportService.get_report(sha)
            status = ReportService.get_status(sha)

            # Generate map
            map_svg = None
            if 'domains_analysis' in result:
                map_svg = generate_world_map(result['domains_analysis'])

            # Find similar sample based on dexofuzzy
            similar_samples = None
            similar_samples_extended = None
            try:
                dexofuzzy_hash = result['dexofuzzy']['apk']
                if dexofuzzy_hash:
                    similar_samples = get_matching_items_by_dexofuzzy(
                        dexofuzzy_hash,
                        25,
                        settings.ELASTICSEARCH_DEXOFUZZY_APK_INDEX, sha)
            except Exception as e:
                logging.error(e)

            if similar_samples:
                res = []
                for sha256, score in similar_samples:
                    apk = SearchService.light_sample_search(sha256)
                    try:
                        vt = apk[0]['source']['vt']
                    except Exception:
                        vt = None
                    res.append((apk[0]['source']['app_name'], apk[0]['source']['handle'], sha256, vt, score))

                    similar_samples_extended = res

            # Find public hunting results
            hunting_matches = Yara.find_public_hunting_matches(sha)

            # Adapt caching depending on the status of the analysis
            cache_retention_time = 2
            if not status['running']:
                cache_retention_time = 600

            # Get timeline
            timeline = get_sample_timeline(sha)

            return render(request, 'front/report.html', {
                'result': result,
                'status': status,
                'map': map_svg,
                'timeline': timeline,
                'cache_key': f'{cache_key}_tpl',
                'hunting_matches': hunting_matches,
                'similar_samples': similar_samples_extended,
                'cache_retention_time': cache_retention_time})
        except Exception as e:
            logging.exception(e)
            return redirect(reverse_lazy('front:home'))


def report_status_view(request, sha256):
    try:
        report_status = ReportService.get_status(sha256)
    except Exception:
        return redirect(reverse_lazy('front:home'))
    return JsonResponse(report_status)


def basic_url_download_view(request):
    if not request.user.is_authenticated:
        return redirect(reverse_lazy('front:home'))

    if request.method == 'POST':
        form = BasicUrlDownloadForm(request.POST)
        if form.is_valid():
            url = form.cleaned_data.get('url')
            try:
                sha256 = ApkService.upload_from_url(url)
            except Exception as e:
                messages.warning(request, e)
                return redirect(reverse_lazy('front:home'))

            return redirect(reverse_lazy('front:report', [sha256]))

    return redirect(reverse_lazy('front:home'))


def basic_upload_view(request):
    if request.method == 'POST':
        form = BasicUploadForm(request.POST, request.FILES)
        if form.is_valid():
            apk = request.FILES['apk']
            try:
                sha256 = ApkService.upload_apk(apk)
            except Exception as e:
                messages.warning(request, e)
                return redirect(reverse_lazy('front:home'))

            return redirect(reverse_lazy('front:report', [sha256]))

    return redirect(reverse_lazy('front:home'))


def similarity_search_view(request, sha256=''):
    if request.method == 'GET':
        form = SimilaritySearchForm(request.GET)
        results = None
        res = []
        if form.is_valid():
            results = form.do_search(sha256)
            for sha256, score in results:
                apk = SearchService.light_sample_search(sha256)
                try:
                    vt = apk[0]['source']['vt']
                except Exception:
                    vt = None

                res.append((apk[0]['source']['app_name'], apk[0]['source']['handle'], sha256, vt, score))

            results = res

        return render(request, 'front/similarity_search.html', {'form': form, 'results': results})


def download_sample_view(request, sha256):
    if not request.user.is_authenticated:
        return redirect(reverse_lazy('front:home'))

    if request.method == 'GET':
        if not ApkService.sample_exists(sha256):
            return redirect(reverse_lazy('front:home'))

        response = HttpResponse(ApkService.download_sample(sha256),
                                content_type="application/vnd.android.package-archive")
        response['Content-Disposition'] = f'inline; filename=pithus_sample_{sha256}.apk'
        return response


def export_report_view(request, sha256):
    if not request.user.is_authenticated:
        return redirect(reverse_lazy('front:home'))

    if request.method == 'GET':
        try:
            result = ReportService.get_report(sha256)
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
    owner = request.user
    if request.method == 'GET':
        my_rules = RulesService.get_rules(owner)

    token, _ = Token.objects.get_or_create(user=owner)

    return render(request, 'front/yara_rules/my_rules.html', context={'my_rules': my_rules, 'my_token': token.key})


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
            RulesService.delete_es_matches(request.user, rule)
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
            RulesService.delete_es_matches(request.user, rule)
            rule.delete()
            messages.success(request, 'Your rule has been deleted.')
            return redirect(reverse_lazy('front:my_rules'))
        except Exception:
            messages.warning(request, 'An error occured while deleting your rule.')
            return redirect(reverse_lazy('front:my_rules'))


def my_retrohunt_view(request, uuid):
    if not request.user.is_authenticated:
        return redirect(reverse_lazy('front:home'))
    # TODO: add a cap on user use
    try:
        async_task(retrohunt, request)
        messages.success(request, 'The retrohunt has been launched.')
    except Exception:
        messages.warning(request, 'An error occured launching retrohunt.')

    return redirect(reverse_lazy('front:my_rules'))


def get_andgrocfg_code(request, sha256, foo):
    if not request.user.is_authenticated:
        return redirect(reverse_lazy('front:home'))

    storage_path = get_andro_cfg_storage_path(sha256)

    out = default_storage.open(f'{storage_path}/{foo}').read()

    if f'{storage_path}/{foo}'.endswith('.raw'):
        out_formatted = highlight(out, JavaLexer(), HtmlFormatter(style=U39bStyle, noclasses=True))
        return HttpResponse(out_formatted, content_type="text/html")
    elif f'{storage_path}/{foo}'.endswith('.png'):
        return HttpResponse(out, content_type='image/bmp')
    else:
        return HttpResponse(out, content_type="image/bmp")


def get_genom(request):
    genom = GenomService.get_genom()
    response = HttpResponse('\n'.join(genom), content_type='text/csv')
    response['Content-Disposition'] = 'inline; filename=pithus_genom.csv'
    return response


def instance_status(request):
    return render(request, 'front/instance_status.html')
