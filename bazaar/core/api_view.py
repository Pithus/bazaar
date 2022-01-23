from django.core.files.storage import default_storage
from django.views.decorators.csrf import csrf_exempt
from rest_framework.parsers import MultiPartParser
from rest_framework.response import Response
from rest_framework.decorators import api_view

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