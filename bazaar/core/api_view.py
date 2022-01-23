from django.core.files.storage import default_storage
from rest_framework.response import Response
from rest_framework.decorators import api_view
from elasticsearch import Elasticsearch
from django.conf import settings
import logging

from bazaar.core.tasks import analyze
from bazaar.core.utils import get_sha256_of_file


@api_view(['GET', 'POST'])
def hello_world(request):
    return Response({"message": "Hello!"})

@api_view(['POST'])
def apkupload(request):
    file_obj = request.data['file']
    sha256 = get_sha256_of_file(file_obj)
    if default_storage.exists(sha256):
        #print(sha256)
        analyze(sha256)
        return Response({"file_sha256": sha256})
    else:
        default_storage.save(sha256, file_obj)
        #print(sha256)
        analyze(sha256)
        return Response({"file_sha256": sha256})

@api_view(['GET', 'POST'])
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
            return Response({"error":e})

@api_view(['GET', 'POST'])
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
            return Response({"error":"Object of type NotFoundError is not JSON serializable"})