from django.urls import path

from bazaar.core.api_view import *

app_name = "core"
urlpatterns = [
    path("report/", view=ReportView.list_reports, name="api-list-reports"),
    path("report/example", view=ReportView.get_example, name="api-report-example"),
    path("report/<str:sha256>", view=ReportView.get_report, name="api-get-report"),
    path("report/<str:sha256>/status", view=ReportView.get_report_status, name="api-report-status"),
    path("report/<str:sha256>/exists", view=ReportView.get_report_exists, name="api-report-exists"),
    path("apk/", view=ApkView.apk_handler, name="api-apk-handler"),
    path("apk/<str:sha256>", view=ApkView.download_sample, name="api-apk-download"),
    path("search/", view=SearchView.search, name="api-seach"),
]
