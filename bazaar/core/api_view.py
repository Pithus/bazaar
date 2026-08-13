import logging
import json

from django.core.files.storage import default_storage
from django.core.cache import cache
from django.http import FileResponse
from django.conf import settings
from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
import rest_framework
from elasticsearch.exceptions import NotFoundError

from bazaar.core.services import ReportService
from bazaar.core.services import ApkService
from bazaar.core.services.apk import ApkException
from bazaar.core.services import SearchService

# Status page imports
from bazaar.core.mobsf import MobSF
from elasticsearch import Elasticsearch
from redis import Redis
from django_q.status import Stat
from django.db import connection
import requests
import vt
from http.client import responses as http_responses

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
        except Exception:
            return Response(
                {"status": "Internal Server Error"},
                status=rest_framework.HTTP_500_INTERNAL_SERVER_ERROR,
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
        except Exception:
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
        except NotFoundError:
            return Response(
                {"message": "Report Not Found"},
                status=rest_framework.status.HTTP_404_NOT_FOUND,
            )
        except Exception:
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
                return Response(
                    {
                        "message": "OK",
                        "requested_hash": sha256,
                    },
                    status=rest_framework.status.HTTP_200_OK,
                )
            else:
                return Response(
                    {
                        "message": "No report found.",
                        "requested_hash": sha256,
                    },
                    status=rest_framework.status.HTTP_404_NOT_FOUND,
                )
        except Exception:
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
        except Exception:
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
        except json.decoder.JSONDecodeError:
            return Response(
                {"message": "Invalid JSON"},
                status=rest_framework.status.HTTP_400_BAD_REQUEST
            )
        return Response(
            {"message": "OK", "result": result},
            status=rest_framework.status.HTTP_200_OK
        )


class StatusView:

    @api_view(['GET'])
    @authentication_classes([])
    @permission_classes([AllowAny])
    @staticmethod
    def get(request):

        status = {}
        message = "OK"
        if connection.ensure_connection() is None:
            dbstatus = True
        else:
            dbstatus = False
            message = "Failed to establish connection to the database"
        status["db"] = {"status": dbstatus, "message": message}

        es = Elasticsearch(
            settings.ELASTICSEARCH_HOSTS,
            basic_auth=(settings.ELASTICSEARCH_USER, settings.ELASTICSEARCH_PASSWORD)
        )
        try:
            es.info(request_timeout=3)
            esstatus = True
            message = "OK"
        except Exception as e:
            esstatus = False
            message = str(e)
        status["elasticsearch"] = {"status": esstatus, "message": message}

        rdstatus = Redis.from_url(settings.Q_CLUSTER["redis"]).ping()
        if rdstatus:
            message = "OK"
        else:
            message = "Cannot reach redis service."
        status["redis"] = {"status": rdstatus, "message": message}

        workers = {}
        clusters = Stat.get_all()
        for cluster in clusters:
            workers[str(cluster.cluster_id)[:8]] = cluster.status
        status["django_q_workers"] = workers

        msf_code = MobSF(settings.MOBSF_TOKEN, settings.MOBSF_SERVER).status()
        if msf_code == 200:
            msfstatus = True
            message = "OK"
        else:
            msfstatus = False
            message = http_responses[msf_code]
        status["mobsf"] = {"status": msfstatus, "message": message}

        headers = {"Auth-Key": settings.MALWARE_BAZAAR_API_KEY}
        data = {"query": "get_info"}
        try:
            r = requests.post("https://mb-api.abuse.ch/api/v1/", headers=headers, data=data)
            if r.status_code == 200:
                mbstatus = True
                message = "OK"
            else:
                mbstatus = False
                message = http_responses[r.status_code]
        except Exception as e:
            mbstatus = False
            message = str(e)
        status["malware_bazaar_api_connection"] = {"status": mbstatus, "message": message}

        vtclient = vt.Client(settings.VT_API_KEY)
        try:
            vtclient.get_json("/files/9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08")
            vtstatus = True
            message = "OK"
        except Exception as e:
            vtstatus = False
            message = e.message
        status["virustotal_api_connection"] = {"status": vtstatus, "message": message}

        return Response(
            {"message": "OK", "status": status},
            status=rest_framework.status.HTTP_200_OK
        )