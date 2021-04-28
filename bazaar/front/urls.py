from django.urls import path

from bazaar.front.view import HomeView, ReportView, basic_upload_view, similarity_search_view, export_report_view, \
    download_sample_view, my_rules_view, my_rule_edit_view, my_rule_create_view, my_rule_delete_view, og_card_view, my_retrohunt_view

app_name = "front"
urlpatterns = [
    path("", view=HomeView.as_view(), name="home"),
    path("report/<str:sha256>", view=ReportView.as_view(), name="report"),
    path("report/<str:sha256>/json", view=export_report_view, name="export_report"),
    path("report/<str:sha256>/card", view=og_card_view, name="og_card"),
    path("apk/", view=basic_upload_view, name="basic_upload"),
    path("apk/<str:sha256>", view=download_sample_view, name="download_sample"),
    path("similar/", view=similarity_search_view, name="similarity_search"),
    path("rules/", view=my_rules_view, name="my_rules"),
    path("rules/new", view=my_rule_create_view, name="my_rule_create"),
    path("rules/<str:uuid>/edit", view=my_rule_edit_view, name="my_rule_edit"),
    path("rules/<str:uuid>/delete", view=my_rule_delete_view, name="my_rule_delete"),
    path("rules/<str:uuid>/retro", view=my_retrohunt_view, name="my_rule_retro")
]
