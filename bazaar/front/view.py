import hashlib
import logging
from collections import Counter
from tempfile import NamedTemporaryFile

import requests
from androcfg.code_style import U39bStyle
from androguard.core.androconf import is_android
from django.conf import settings
from django.contrib import messages
from django.core.cache import cache
from django.core.files.storage import default_storage
from django.http import HttpResponse, JsonResponse
from django.http.response import HttpResponseBadRequest
from django.shortcuts import redirect, render
from django.utils import timezone
from django.utils.decorators import method_decorator
from django.views.decorators.cache import cache_page
from django.views.decorators.csrf import csrf_exempt
from django.views.generic import View
from django_q.tasks import async_task
from elasticsearch import Elasticsearch
from elasticsearch.helpers.actions import scan
from pygments import highlight
from pygments.formatters import HtmlFormatter
from pygments.lexers.jvm import JavaLexer
from rest_framework.authtoken.models import Token
from rest_framework.reverse import reverse_lazy

from bazaar.core.models import Bookmark, Yara
from bazaar.core.tasks import analyze, retrohunt
from bazaar.core.utils import get_matching_items_by_dexofuzzy, get_sha256_of_file
from bazaar.front.forms import (
    BasicUploadForm,
    BasicUrlDownloadForm,
    SearchForm,
    SimilaritySearchForm,
)
from bazaar.front.og import generate_og_card
from bazaar.front.utils import (
    compute_status,
    generate_world_map,
    get_andro_cfg_storage_path,
    get_sample_timeline,
    get_similarity_matrix,
    transform_hl_results,
    transform_results,
)

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
                          'max_size': settings.MAX_APK_UPLOAD_SIZE,
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
            similar_samples_extended = None
            try:
                dexofuzzy_hash = result['dexofuzzy']['apk']
                if dexofuzzy_hash:
                    similar_samples = get_matching_items_by_dexofuzzy(
                        dexofuzzy_hash,
                        25,
                        settings.ELASTICSEARCH_DEXOFUZZY_APK_INDEX, sha)
            except Exception:
                pass

            if similar_samples:
                res = []
                for sha256, score in similar_samples:
                    apk = get_sample_light(sha256)
                    try:
                        vt = apk[0]['source']['vt']
                    except:
                        vt = None
                    res.append((apk[0]['source']['app_name'], apk[0]['source']['handle'], sha256, vt, score))

                    similar_samples_extended = res

            # Find public hunting results
            hunting_matches = Yara.find_public_hunting_matches(sha)

            # Adapt caching depending on the status of the analysis
            cache_retention_time = 5
            if not status['running']:
                cache_retention_time = 600

            # Get timeline
            timeline = get_sample_timeline(sha)

            # Check if the sample is already bookmarked
            if request.user.is_authenticated:
                is_bookmarked = get_user_bookmark_by_hash(request, sha)
            else:
                is_bookmarked = False

            return render(request, 'front/report.html', {
                'result': result,
                'status': status,
                'map': map_svg,
                'timeline': timeline,
                'cache_key': f'{cache_key}_tpl',
                'hunting_matches': hunting_matches,
                'similar_samples': similar_samples,
                'cache_retention_time': cache_retention_time,
                'is_bookmarked': is_bookmarked})
        except Exception as e:
            logging.exception(e)
            return redirect(reverse_lazy('front:home'))


def basic_url_download_view(request):
    if not request.user.is_authenticated:
        return redirect(reverse_lazy('front:home'))
    if request.method == 'POST':
        form = BasicUrlDownloadForm(request.POST)
        if form.is_valid():
            url = form.cleaned_data.get('url')
            res = requests.get(url, stream=True)

            if res.status_code not in [200, 301, 302]:
                messages.warning(request, 'URL is not available.')
                return redirect(reverse_lazy('front:home'))

            sha256_hash = hashlib.sha256()
            with NamedTemporaryFile() as tmp:
                for chunk in res.iter_content(chunk_size=16 * 1024):
                    tmp.write(chunk)
                    sha256_hash.update(chunk)

                sha256 = str(sha256_hash.hexdigest()).lower()
                if is_android(tmp.name) != 'APK':
                    messages.warning(request, 'Submitted file is not a valid APK.')

                if default_storage.exists(sha256):
                    return redirect(reverse_lazy('front:report', [sha256]))
                else:
                    default_storage.save(sha256, tmp)
                    analyze(sha256)
                    return redirect(reverse_lazy('front:report', [sha256]))

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


def similarity_search_view(request, sha256=''):
    if request.method == 'GET':
        form = SimilaritySearchForm(request.GET)
        results = None
        res = []
        if form.is_valid():
            results = form.do_search(sha256)
            for sha256, score in results:
                apk = get_sample_light(sha256)
                try:
                    vt = apk[0]['source']['vt']
                except:
                    vt = None

                res.append((apk[0]['source']['app_name'], apk[0]['source']['handle'], sha256, vt, score))

            results = res

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


def get_user_bookmarks(request):
    return Bookmark.objects.filter(owner=request.user)


def enrich_bookmarks(bookmarks):
    res = []
    for sample in bookmarks:
        apk = get_sample_light(sample.sample)
        res.append(apk)
    return res


def get_user_bookmark_by_hash(request, sha):
    bookmark = Bookmark.objects.filter(owner=request.user, sample=sha)
    return bookmark


def add_bookmark_sample_view(request, sha256):
    if not request.user.is_authenticated:
        return redirect(reverse_lazy('front:home'))

    if request.method == 'GET':
        user_bookmarks = get_user_bookmarks(request)
        if not user_bookmarks.filter(sample=sha256):
            new_bookmark = Bookmark.objects.create(sample=sha256, owner=request.user)
            try:
                new_bookmark.save()
                user_bookmarks = get_user_bookmarks(request)
            except Exception as e:
                logging.exception(e)

    return redirect(reverse_lazy('front:report', [sha256]))


def remove_bookmark_sample_view(request, sha256):
    if not request.user.is_authenticated:
        return redirect(reverse_lazy('front:home'))

    if request.method == 'GET':
        bookmark = get_user_bookmark_by_hash(request, sha256)
        try:
            bookmark.delete()
        except Exception as e:
            logging.exception(e)

    return redirect(reverse_lazy('front:report', [sha256]))


def get_last_samples():
    query = {
        "query": {
            "query_string": {
                "default_field": "sha256",
                "query": "*"
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
        "size": 5,
    }
    es = Elasticsearch(settings.ELASTICSEARCH_HOSTS)
    try:
        raw_results = es.search(index=settings.ELASTICSEARCH_APK_INDEX, body=query)
        results = transform_results(raw_results)
        return results
    except Exception as e:
        return []


def workspace_view(request):
    if not request.user.is_authenticated:
        return redirect(reverse_lazy('front:home'))

    my_rules = None
    my_bookmarks = None
    if request.method == 'GET':
        # TODO: refactor so there is only one call for all the rules, then filter by user and by score and output those in the tables
        apk_count = get_count_apks()
        malicious = get_malicious_samples_count()
        count = {
            "apks": apk_count,
            "malicious": malicious
        }
        my_rules = get_rules(request)
        my_bookmarks = enrich_bookmarks(get_user_bookmarks(request))
        last_samples = get_last_samples()
        highest_matching_rules = get_best_rules()
        trending_malwares = get_trending_malware()
        trends = {
            'samples': last_samples, 'rules': highest_matching_rules, 'trending_malwares': trending_malwares
        }

    owner = request.user
    token, _ = Token.objects.get_or_create(user=owner)
    return render(request, 'front/workspace/workspace_base.html',
                  context={'my_rules': my_rules, 'my_token': token,
                           'bookmarked_samples': my_bookmarks, 'trends': trends,
                           'count': count})


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
            return render(request, 'front/workspace/my_rule_edit.html', {'form': new_rule})
        return redirect(reverse_lazy('front:workspace'))

    return render(request, 'front/workspace/my_rule_edit.html', {'form': new_rule})


def my_rule_edit_view(request, uuid):
    if not request.user.is_authenticated:
        return redirect(reverse_lazy('front:home'))

    if request.method == 'GET':
        rule = Yara.objects.get(id=uuid)
        new_rule = YaraCreateForm(instance=rule)
        return render(request, 'front/workspace/my_rule_edit.html', {'form': new_rule, 'edit': True})

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
            return render(request, 'front/workspace/my_rule_edit.html', {'form': new_rule})
        return redirect(reverse_lazy('front:workspace'))
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
            return redirect(reverse_lazy('front:workspace'))
        except Exception as e:
            logging.exception(e)
            return redirect(reverse_lazy('front:workspace'))


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


def get_count_apks():
    query = {
        "aggs": {
            "type_value": {
                "value_count": {
                    "field": "apk_hash.keyword"
                }
            }
        }
    }
    es = Elasticsearch(settings.ELASTICSEARCH_HOSTS)

    try:
        count = es.search(index=settings.ELASTICSEARCH_APK_INDEX, body=query)['aggregations']['type_value']['value']
        return count
    except:
        return -1


def get_trending_malware():
    query = {
        "query": {
            "bool": {
                "must": [],
                "filter": [
                    {
                        "bool": {
                            "should": [
                                {
                                    "range": {
                                        "vt_report.attributes.popular_threat_classification.popular_threat_name.count": {
                                            "gt": 1
                                        }
                                    }
                                }
                            ],
                            "minimum_should_match": 1
                        }
                    }
                ],
                "should": [],
                "must_not": []
            }
        },
        "size": 5000,
        "_source": "vt_report.attributes.popular_threat_classification.popular_threat_name.value",
        "sort": [
            {
                "vt_report.attributes.popular_threat_classification.popular_threat_name.count": {
                    "order": "desc"
                }
            }
        ]
    }
    es = Elasticsearch(settings.ELASTICSEARCH_HOSTS)
    try:
        results = es.search(index=settings.ELASTICSEARCH_APK_INDEX, body=query)['hits']['hits']
        return Counter(value['_source']['vt_report']['attributes']
                       ['popular_threat_classification']['popular_threat_name'][0]['value'] for value in results).most_common(5)

    except Exception:
        return []


def get_malicious_samples_count():
    query = {
        "query": {
            "bool": {
                "must": [],
                "filter": [
                    {
                        "bool": {
                            "should": [
                                {
                                    "range": {
                                        "vt.malicious": {
                                            "gt": 1
                                        }
                                    }
                                }
                            ],
                            "minimum_should_match": 1
                        }
                    }
                ],
                "should": [],
                "must_not": []
            }
        },
        "size": 5000,
        "_source": "vt",
        "sort": [
            {
                "vt.malicious": {
                    "order": "desc"
                }
            }
        ]
    }
    es = Elasticsearch(settings.ELASTICSEARCH_HOSTS)
    try:
        results = es.search(index=settings.ELASTICSEARCH_APK_INDEX, body=query)['hits']['hits']
        res = Counter(value['_source']['vt']['malicious'] for value in results)
        # FIXME: total() doesn't seem to work, idk why
        return sum(res.values())
    except:
        return -1


def get_best_rules():
    es = Elasticsearch(settings.ELASTICSEARCH_HOSTS)
    yara_rules = Yara.objects.all()
    my_rules = []
    public_es_index, _ = Yara.get_es_index_names()
    # TODO: note fo later: in an ideal world, it would be nice to have the matches.matching_files be set on keyword=true for Elastic search so we can retreive the result sorted instead of sorting them on our own. See: https://stackoverflow.com/questions/63784500/text-fields-are-not-optimised-for-operations-that-require-per-document-elastic
    q = {
        "query": {
            "bool": {
                "must": [],
                "filter": [
                    {
                        "bool": {
                            "should": [
                                {
                                    "range": {
                                        "matches.matching_files": {
                                            "gt": 1
                                        }
                                    }
                                }
                            ],
                            "minimum_should_match": 1
                        }
                    }
                ],
                "should": [],
                "must_not": []
            }
        },
        "size": 5000,
    }
    public_matches = None
    try:
        public_matches = es.search(index=public_es_index, body=q)['hits']['hits']
        for rule in yara_rules:
            my_rule = {
                'rule': rule,
                'matching_date': '',
                'matches': [],
            }
            if public_matches:
                for match in public_matches:
                    if match['_source']['rule'] == str(rule.id):
                        m = match['_source']
                        m['sample'] = get_sample_light(match['_source']['matches']['apk_id'])
                        my_rule['matches'].append(m)
            if len(my_rule['matches']) > 1:
                my_rules.append(my_rule)

        return my_rules
    except:
        return []


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

    return redirect(reverse_lazy('front:workspace'))


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
    es = Elasticsearch(settings.ELASTICSEARCH_HOSTS)
    entire_genom = []
    for report in scan(
        es,
        query={"query": {"match_all": {}}},
        index=settings.ELASTICSEARCH_APK_INDEX,
    ):
        sha256 = report.get('_source').get('sha256')
        genom = None
        threat = 'unknown'
        try:
            genom = report.get('_source').get('andro_cfg').get('genom')
            threat = report.get('_source').get('vt_report').get('attributes').get(
                'popular_threat_classification').get('suggested_threat_label')
        except Exception:
            pass
        if genom:
            entire_genom.append(f'{sha256}-{threat},{genom}')

    response = HttpResponse('\n'.join(entire_genom), content_type='text/csv')
    response['Content-Disposition'] = f'inline; filename=pithus_genom.csv'
    return response
