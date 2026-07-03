import logging
import hashlib
import requests

from django.conf import settings
from django.core.files.storage import default_storage
from django.core.cache import cache
from django.http import JsonResponse, HttpResponse, FileResponse
from rest_framework.reverse import reverse_lazy
from elasticsearch import Elasticsearch # TODO: remove this, it should not appear here in this file
from rest_framework.authentication import TokenAuthentication
from rest_framework.decorators import api_view, authentication_classes, permission_classes, throttle_classes
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.response import Response
import rest_framework
from rest_framework.throttling import UserRateThrottle

from bazaar.core.services.report import ReportService
from bazaar.core.services.apk import ApkService, ApkException
from bazaar.core.tasks import analyze
from bazaar.core.utils import get_sha256_of_file
from bazaar.front.utils import transform_hl_results

from androguard.core.androconf import is_android
from tempfile import NamedTemporaryFile


@api_view(['GET', 'POST'])
def hello_world(request):
    return Response({"message": "Hello!"})

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

    @staticmethod
    def upload_apk(request) -> Response:
        try:
            apk = request.FILES['apk']
            sha256 = ApkService.upload_apk(apk)
        except ApkException as e:
            return Response(
                {"status": f"{e}"},
                status=rest_framework.status.HTTP_400_BAD_REQUEST
            )
        except Exception as e:
            return Response(
                status=rest_framework.status.HTTP_500_INTERNAL_SERVER_ERROR
            )
        return Response(
            {"status": "OK", "file_hash": f"{sha256}"},
            status=rest_framework.status.HTTP_200_OK,
        )

    @api_view(["GET"])
    @staticmethod
    def download_sample(request, sha256) -> Response:
        if ApkService.sample_exists(sha256):
            response = FileResponse(
                ApkService.download_sample(sha256),
                content_type="application/vnd.android.package-archive",
                status=rest_framework.status.HTTP_200_OK,
            )
            response['Content-Disposition'] = f'inline; filename=pithus_sample_{sha256}.apk'
            return response
        return Response(
            {"status": "Requested file does not exist."},
            status=rest_framework.status.HTTP_404_NOT_FOUND,
        )