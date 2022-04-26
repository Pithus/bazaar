from bazaar.core.api_view import *
from django.urls import path

app_name = "core"
urlpatterns = [
    #path("upload", view=APKFileUploadView.as_view(), name="upload-apk"),
    path("hello",hello_world,name="bazaar-api"),
    path("upload",apkupload,name="bazaar-api"),
    path("report/<str:sha256>",apk_analysis_report,name="bazaar-api"),
    path("status/<str:sha256>",analysis_tasks_status,name="bazaar-api")
]