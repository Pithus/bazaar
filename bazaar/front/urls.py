from django.urls import path

from bazaar.front.view import HomeView, ReportView

app_name = "front"
urlpatterns = [
    path("", view=HomeView.as_view(), name="home"),
    path("report/<str:sha256>", view=ReportView.as_view(), name="report"),
]
