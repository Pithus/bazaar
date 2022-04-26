import logging

from django.conf import settings
from django.core.files.storage import default_storage
from elasticsearch import Elasticsearch
from rest_framework.authentication import TokenAuthentication
from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from bazaar.core.tasks import analyze
from bazaar.core.utils import get_sha256_of_file


@api_view(['GET', 'POST'])
@authentication_classes([TokenAuthentication])
@permission_classes([IsAuthenticated])
def hello_world(request):
    return Response({"message": "Hello!"})


@api_view(['POST'])
@authentication_classes([TokenAuthentication])
@permission_classes([IsAuthenticated])
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
@authentication_classes([TokenAuthentication])
@permission_classes([IsAuthenticated])
def apk_analysis_report(request, sha256):
    if not request.user.is_authenticated:
        return Response({"user": "is_authenticated"})

    if request.method == 'GET':
        es = Elasticsearch(settings.ELASTICSEARCH_HOSTS)
        try:
            result = es.get(index=settings.ELASTICSEARCH_APK_INDEX, id=sha256)['_source']
            return Response(result)
        except Exception as e:
            logging.exception(e)
            return Response({"error": e})


@api_view(['GET'])
@authentication_classes([TokenAuthentication])
@permission_classes([IsAuthenticated])
def analysis_tasks_status(request, sha256):
    if not request.user.is_authenticated:
        return Response({"user": "is_authenticated"})

    if request.method == 'GET':
        es = Elasticsearch(settings.ELASTICSEARCH_HOSTS)
        try:
            result = es.get(index=settings.ELASTICSEARCH_TASKS_INDEX, id=sha256)['_source']
            return Response(result)
        except Exception as e:
            logging.exception(e)
            return Response({"error": "Object of type NotFoundError is not JSON serializable"})
