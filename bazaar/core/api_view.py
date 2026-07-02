import logging
import hashlib
import requests

from django.conf import settings
from django.core.files.storage import default_storage
from django.core.cache import cache
from django.http import JsonResponse
from rest_framework.reverse import reverse_lazy
from elasticsearch import Elasticsearch # TODO: remove this, it should not appear here in this file
from rest_framework.authentication import TokenAuthentication
from rest_framework.decorators import api_view, authentication_classes, permission_classes, throttle_classes
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.response import Response
import rest_framework
from rest_framework.throttling import UserRateThrottle

from bazaar.core.services.report import ReportService
from bazaar.core.tasks import analyze
from bazaar.core.utils import get_sha256_of_file
from bazaar.front.utils import transform_hl_results

from androguard.core.androconf import is_android
from tempfile import NamedTemporaryFile



@api_view(['GET', 'POST'])
def hello_world(request):
    return Response({"message": "Hello!"})


@api_view(['POST'])
def apk_upload(request):
    file_obj = request.data['file']
    sha256 = get_sha256_of_file(file_obj)
    if default_storage.exists(sha256):
        return Response({"file_sha256": sha256})
    else:
        default_storage.save(sha256, file_obj)
        analyze(sha256)
        return Response({"file_sha256": sha256})


@api_view(['GET'])
def url_download(request):
    if not request.user.is_authenticated:
        return Response({"user": "is_authenticated"})
    else:
        res = requests.get(request.data['url'])

        if res.status_code not in [200, 301, 302]:
            return Response({"url": "URL is not available."})

        sha256_hash = hashlib.sha256()
        with NamedTemporaryFile() as tmp:
            for chunk in res.iter_content(chunk_size=16 * 1024):
                tmp.write(chunk)
                sha256_hash.update(chunk)

            sha256 = str(sha256_hash.hexdigest()).lower()
            if is_android(tmp.name) != 'APK':
                return Response({"apk": "not a valid APK"})

            sha256 = get_sha256_of_file(tmp)
            if default_storage.exists(sha256):
                # analyze(sha256, force=True)
                return Response({"file_sha256": sha256})
            else:
                default_storage.save(sha256, tmp)
                analyze(sha256)
                return Response({"file_sha256": sha256})


@api_view(['GET'])
def apk_analysis_report(request, sha256):
    if not request.user.is_authenticated:
        return Response({"user": "is_authenticated"})

    if request.method == 'GET':
        es = Elasticsearch(settings.ELASTICSEARCH_HOSTS, basic_auth=(settings.ELASTICSEARCH_USER, settings.ELASTICSEARCH_PASSWORD))

        try:
            result = es.get(index=settings.ELASTICSEARCH_APK_INDEX, id=sha256)['_source']
            return Response(result)
        except Exception as e:
            logging.exception(e)
            return Response({"error": e})


@api_view(['GET'])
def analysis_tasks_status(request, sha256):
    if not request.user.is_authenticated:
        return Response({"user": "is_authenticated"})

    if request.method == 'GET':
        es = Elasticsearch(settings.ELASTICSEARCH_HOSTS, basic_auth=(settings.ELASTICSEARCH_USER, settings.ELASTICSEARCH_PASSWORD))
        try:
            result = es.get(index=settings.ELASTICSEARCH_TASKS_INDEX, id=sha256)['_source']
            return Response(result)
        except Exception as e:
            logging.exception(e)
            return Response({"error": "Object of type NotFoundError is not JSON serializable"})


@api_view(['POST'])
def search(request):
    user_query = request.data
    if not user_query or 'q' not in user_query:
        return Response([])
    q = user_query.get('q')
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
        "sort": {"analysis_date": "desc"},
        "_source": ["sha256", "uploaded_at", "handle", "app_name",
                    "version_code", "size", "dexofuzzy.apk", "quark.threat_level", "vt", "malware_bazaar",
                    "is_signed", "frosting_data.is_frosted", "features"],
        "size": 150,
    }

    es = Elasticsearch(settings.ELASTICSEARCH_HOSTS, basic_auth=(settings.ELASTICSEARCH_USER, settings.ELASTICSEARCH_PASSWORD))
    try:
        raw_results = es.search(index=settings.ELASTICSEARCH_APK_INDEX, body=query)
        results = transform_hl_results(raw_results)
        return Response(results)
    except Exception as e:
        return Response([])


class ReportView:

    @api_view(["GET"])
    @staticmethod
    def list_reports(request) -> Response:
        try:
            reports = ReportService.list_reports()
            return Response(
                {
                    "status": "OK",
                    "reports": reports
                },
                status=rest_framework.status.HTTP_200_OK,
            )
        except Exception as e:
            return Response(
                {"status": "Internal Server Error"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

    @api_view(["GET"])
    @staticmethod
    def get_report(request, *args, **kwargs) -> Response:
        try:
            sha256 = kwargs['sha256']

            cache_key = f'report_{sha256}'
            if request.user.is_authenticated:
                cache_key = f'report_{sha256}_authenticated'

            cached_report = cache.get(cache_key)
            if cached_report:
                report = cached_report
            else:
                report = ReportService.get_report(sha256)
                report_status = ReportService.get_status(sha256)

                if report_status["running"] or not report_status["analysis_launched"]:
                    cache.set(cache_key, report, timeout=5)
                else:
                    cache.set(cache_key, report, timeout=6000)

            return Response(
                {
                    "status": "OK",
                    "report": report,
                },
                status=rest_framework.status.HTTP_200_OK,
            )
        except Exception as e:
            raise
            return Response(
                {"status": "Internal Server Error"},
                status=rest_framework.status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

    @api_view(["GET"])
    @staticmethod
    def get_report_status(request, sha256) -> Response:
        try:
            report_status = ReportService.get_status(sha256)
            detailed_status = ReportService.get_detailed_status(sha256)
            return Response(
                {
                    "status": "OK",
                    "report_status": report_status,
                    "detailed_status": detailed_status,
                },
                status=rest_framework.status.HTTP_200_OK,
            )
        except Exception as e:
            raise
            return Response(
                {"status": "Internal Server Error"},
                status=rest_framework.status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

    @api_view(["GET"])
    @staticmethod
    def get_example(request) -> Response:
        try:
            report = ReportService.get_example()
            return Response(
                {
                    "status": "OK",
                    "report": report
                },
                status=rest_framework.status.HTTP_200_OK,
            )
        except Exception as e:
            logging.error(e)
            return Response(
                {"status": "Internal Server Error"},
                status=rest_framework.status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


class ApkView:

    @api_view(["GET", "POST"])
    @staticmethod
    def apk_handler(request):
        if request.method == "GET":
            return ApkView.list_apk(request)
        elif request.method == "POST":
            return ApkView.upload_apk(request)
        else:
            return Response(
                {"status": "KO"},
                status=rest_framework.status.HTTP_405_METHOD_NOT_ALLOWED,
            )

    @api_view(["GET"])
    @staticmethod
    def list_apk(request) -> Response:
        return Response(
            status=rest_framework.status.HTTP_200_OK,
        )

    @api_view(["POST"])
    @staticmethod
    def upload_apk(request, apk) -> Response:
        return Response(
            status=rest_framework.status.HTTP_200_OK,
        )

    @api_view(["GET"])
    @staticmethod
    def download_apk(request, sha256) -> Response:
        return Response(
            status=rest_framework.status.HTTP_200_OK,
        )