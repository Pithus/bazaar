from django.urls import path

from bazaar.front.view import (
    HomeView,
    ReportView,
    basic_upload_view,
    add_bookmark_sample_view,
    remove_bookmark_sample_view,
    download_sample_view,
    export_report_view,
    get_andgrocfg_code,
    get_genom,
    my_retrohunt_view,
    my_rule_create_view,
    my_rule_delete_view,
    my_rule_edit_view,
    workspace_view,
    og_card_view,
    similarity_search_view,
)

app_name = "front"
urlpatterns = [
    path("", view=HomeView.as_view(), name="home"),
    path("report/<str:sha256>", view=ReportView.as_view(), name="report"),
    path("report/<str:sha256>/json", view=export_report_view, name="export_report"),
    path("report/<str:sha256>/card", view=og_card_view, name="og_card"),
    path("apk/", view=basic_upload_view, name="basic_upload"),
    path("apk/<str:sha256>", view=download_sample_view, name="download_sample"),
    path("similar/", view=similarity_search_view, name="similarity_search"),
    path("similar/<str:sha256>", view=similarity_search_view, name="similarity_search"),
    path("workspace/", view=workspace_view, name="workspace"),
    path("rules/new", view=my_rule_create_view, name="my_rule_create"),
    path("rules/<str:uuid>/edit", view=my_rule_edit_view, name="my_rule_edit"),
    path("rules/<str:uuid>/delete", view=my_rule_delete_view, name="my_rule_delete"),
    path("rules/<str:uuid>/retro", view=my_retrohunt_view, name="my_rule_retro"),
    path("androcfg/<str:sha256>/<path:foo>", view=get_andgrocfg_code, name="get_andgrocfg_code"),
    path("androcfg/all", view=get_genom, name="get_genom"),
    path("apk/<str:sha256>/bookmark", view=add_bookmark_sample_view, name="bookmark_sample"),
    path("apk/<str:sha256>/bookmark/remove", view=remove_bookmark_sample_view, name="remove_bookmark_sample")
]
