import logging
import hashlib
import requests
import json

from django.conf import settings
from django.core.files.storage import default_storage
from django.core.cache import cache
from django.http import JsonResponse, HttpResponse, FileResponse
from rest_framework.reverse import reverse_lazy
from rest_framework.authentication import TokenAuthentication
from rest_framework.decorators import api_view, authentication_classes, permission_classes, throttle_classes
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.response import Response
import rest_framework
from rest_framework.throttling import UserRateThrottle

from bazaar.core.services import ReportService
from bazaar.core.services import ApkService
from bazaar.core.services.apk import ApkException
from bazaar.core.services import SearchService

from bazaar.core.tasks import analyze
from bazaar.core.utils import get_sha256_of_file
from bazaar.core.utils import transform_hl_results

from androguard.core.androconf import is_android
from tempfile import NamedTemporaryFile


@api_view(['GET', 'POST'])
def hello_world(request):
    return Response({"message": "Hello!"})


class ReportView:

    @api_view(["GET"])
    @staticmethod
    def list_reports(request) -> Response:
        try:
            reports = ReportService.list_reports()
            return Response(
                {
                    "message": "OK",
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
                    "message": "OK",
                    "report": report,
                },
                status=rest_framework.status.HTTP_200_OK,
            )
        except Exception as e:
            raise
            return Response(
                {"message": "Internal Server Error"},
                status=rest_framework.status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

    @api_view(["GET"])
    @authentication_classes([])
    @permission_classes([])
    @staticmethod
    def get_report_status(request, sha256) -> Response:
        try:
            report_status = ReportService.get_status(sha256)
            detailed_status = ReportService.get_detailed_status(sha256)
            return Response(
                {
                    "message": "OK",
                    "report_status": report_status,
                    "detailed_status": detailed_status,
                },
                status=rest_framework.status.HTTP_200_OK,
            )
        except:
            return Response(
                {"message": "Internal Server Error"},
                status=rest_framework.status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

    @api_view(["GET"])
    @authentication_classes([])
    @permission_classes([AllowAny])
    @staticmethod
    def get_report_exists(request, sha256) -> Response:
        try:
            if default_storage.exists(sha256):
                return Response({
                        "message": "OK",
                        "requested_hash": sha256,
                    },
                    status=rest_framework.status.HTTP_200_OK,
                )
            else:
                return Response({
                        "message": "No report found.",
                        "requested_hash": sha256,
                    },
                    status=rest_framework.status.HTTP_404_NOT_FOUND,
                )
        except:
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
                {"message": "Method Not Allowed."},
                status=rest_framework.status.HTTP_405_METHOD_NOT_ALLOWED,
            )

    # Not sure if this is a good idea to implement, leaving NOT IMPLEMENTED for now
    @staticmethod
    def list_apk(request) -> Response:
        return Response(
            {"message": "Not Implemented"},
            status=rest_framework.status.HTTP_501_NOT_IMPLEMENTED,
        )

    @staticmethod
    def upload_apk(request) -> Response:
        try:
            apk = request.FILES['apk']
            sha256 = ApkService.upload_apk(apk)
        except ApkException as e:
            return Response(
                {"message": f"{e}"},
                status=rest_framework.status.HTTP_400_BAD_REQUEST
            )
        except Exception as e:
            return Response(
                status=rest_framework.status.HTTP_500_INTERNAL_SERVER_ERROR
            )
        return Response(
            {"message": "OK", "file_hash": f"{sha256}"},
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
            {"message": "Requested file does not exist."},
            status=rest_framework.status.HTTP_404_NOT_FOUND,
        )


class SearchView:

    @api_view(['POST'])
    @staticmethod
    def search(request):
        user_query = request.data
        if not user_query or 'q' not in user_query:
            return Response(
                {"message": "Invalid search query."},
                status=rest_framework.status.HTTP_406_NOT_ACCEPTABLE
            )
        q = user_query.get('q')
        try:
            result = SearchService.search(q)
        except json.decoder.JSONDecodeError as e:
            return Response(
                {"message": "Invalid JSON"},
                status=rest_framework.status.HTTP_400_BAD_REQUEST
            )
        return Response(
            {"message": "OK", "result": result},
            status=rest_framework.status.HTTP_200_OK
        )