from django.urls import path

from bazaar.core.api_view import *

app_name = "core"
urlpatterns = [
    path("hello", hello_world, name="bazaar-api"),
    path("upload", apk_upload, name="bazaar-api"),
    path("report/<str:sha256>", apk_analysis_report, name="bazaar-api"),
    path("status/<str:sha256>", analysis_tasks_status, name="bazaar-api")
]
