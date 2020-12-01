from django.views.decorators.csrf import csrf_exempt
from rest_framework import views
from rest_framework.parsers import MultiPartParser
from rest_framework.response import Response
from django.core.files.storage import default_storage
from rest_framework.status import HTTP_409_CONFLICT, HTTP_201_CREATED

from bazaar.core.tasks import analyze
from bazaar.core.utils import get_sha256_of_file


class APKFileUploadView(views.APIView):
    parser_classes = [MultiPartParser]
    authentication_classes = []
    permission_classes = []

    @csrf_exempt
    def put(self, request):
        file_obj = request.data['file']
        print(request.data)
        sha256 = get_sha256_of_file(file_obj)
        print(sha256)
        if default_storage.exists(sha256):
            analyze(sha256)
            return Response(status=HTTP_409_CONFLICT)
        else:
            default_storage.save(sha256, file_obj)
            analyze(sha256)
            return Response(status=HTTP_201_CREATED)
