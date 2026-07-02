from django.urls import path

from bazaar.core.api_view import *

app_name = "core"
urlpatterns = [
    path("report/", view=ReportView.list_reports, name="api-list-reports"),
    path("report/example", view=ReportView.get_example, name="api-report-example"),
    path("report/<str:sha256>", view=ReportView.get_report, name="api-get-report"),
    path("report/<str:sha256>/status", view=ReportView.get_report_status, name="api-report-status"),
    path("apk/", view=ApkView.apk_handler, name="api-apk-handler"),
    path("apk/<str:sha256>", view=ApkView.download_apk, name="api-apk-download"),


    # path("status/<str:sha256>", analysis_tasks_status, name="bazaar-api"),
    # path("exists/<str:sha256>", sample_exists, name="bazaar-api"),
    # path("search/", search, name="bazaar-api"),
]
