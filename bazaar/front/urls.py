from django.urls import path

from bazaar.front.view import HomeView, ReportView, basic_upload_view, similarity_search_view, export_report_view, \
    download_sample_view, og_card_view

app_name = "front"
urlpatterns = [
    path("", view=HomeView.as_view(), name="home"),
    path("report/<str:sha256>", view=ReportView.as_view(), name="report"),
    path("report/<str:sha256>/json", view=export_report_view, name="export_report"),
    path("report/<str:sha256>/card", view=og_card_view, name="og_card"),
    path("apk/", view=basic_upload_view, name="basic_upload"),
    path("apk/<str:sha256>", view=download_sample_view, name="download_sample"),
    path("similar/", view=similarity_search_view, name="similarity_search"),
]
