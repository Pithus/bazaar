from django.urls import path

from bazaar.front.view import HomeView, ReportView, basic_upload_view

app_name = "front"
urlpatterns = [
    path("", view=HomeView.as_view(), name="home"),
    path("report/<str:sha256>", view=ReportView.as_view(), name="report"),
    path("apk/", view=basic_upload_view, name="basic_upload"),
]
