import os
import pytest
from io import BytesIO

from .conftest import sha256, uuid
from django.conf import settings
from django.contrib.auth.models import AnonymousUser

from bazaar.core.api_view import (
    ReportView as ApiReportView,
    ApkView,
    SearchView,
)

from bazaar.front.view import (
    HomeView,
    ReportView,
    export_report_view,
    og_card_view,
    report_status_view,
    basic_url_download_view,
    basic_upload_view,
    similarity_search_view,
    download_sample_view,
    export_report_view,
    og_card_view,
    my_rules_view,
    my_rule_create_view,
    my_rule_edit_view,
    my_rule_delete_view,
    my_retrohunt_view,
    get_andgrocfg_code,
    get_genom
)

class MetaIter(type):
    def __iter__(self):
        for attr in dir(self):
            if not attr.startswith("__"):
                yield attr


class IterableMock(Mock, metaclass=MetaIter):

    def __init__(self, *args, **kwargs):
        super().__init__(args, kwargs)


@pytest.mark.django_db
@pytest.mark.parametrize("view, url, args, kwargs", [
    pytest.param(
        HomeView.as_view(), "/report/", [], {},
        marks=pytest.mark.skip(reason="No auth required")
    ),
    pytest.param(
        ReportView.as_view(), f"/report/{sha256}", [], {"sha256": sha256},
        marks=pytest.mark.skip(reason="No auth required")
    ),
    pytest.param(
        export_report_view, f"/report/{sha256}/json", [], {"sha256": sha256},
        marks=pytest.mark.skip(reason="No auth required")
    ),
    pytest.param(
        og_card_view, f"/report/{sha256}/card", [], {"sha256": sha256},
        marks=pytest.mark.skip(reason="No auth required")
    ),
    pytest.param(
        report_status_view, f"/report/{sha256}/status", [], {"sha256": sha256},
        marks=pytest.mark.skip(reason="No auth required")
    ),
    pytest.param(
        basic_upload_view, "/apk/", [], {},
        marks=pytest.mark.skip(reason="No auth required")
    ),
    pytest.param(
        basic_url_download_view, "/url/", [], {},
        marks=pytest.mark.skip(reason="No auth required")
    ),
    (download_sample_view, f"/apk/{sha256}", [sha256], {}
    ),
    pytest.param(
        similarity_search_view, f"/similar/{sha256}", [], {"sha256": sha256},
        marks=pytest.mark.skip(reason="No auth required")
    ),
    (my_rules_view, "/rules/", [], {}),
    (my_rule_create_view, "/rules/new", [], {}),
    (my_rule_edit_view, f"/rules/{uuid}/edit", [uuid], {}),
    (my_rule_delete_view, f"/rules/{uuid}/delete", [], {"uuid": uuid}),
    (my_retrohunt_view, f"/rules/{uuid}/retro", [uuid], {}),
    (get_andgrocfg_code, f"/androcfg/{sha256}/path", [sha256, "path"], {}),
    pytest.param(
        get_genom, "/androcfg/all", [], {},
        marks=pytest.mark.skip(reason="No auth required")
    ),
])
def test_permissions(rf, user, view, url, args, kwargs):
  
    request = rf.get(url)
    request.user = AnonymousUser()

    response = view(request, *args, **kwargs)
    assert response.status_code == 302


@pytest.mark.django_db
@pytest.mark.parametrize("view, url, valid_status, args, kwargs", [
    (ApiReportView.list_reports, "/api/report/", 200, [], {}),
    (ApiReportView.get_example, "/api/report/example", 200, [], {}),
    (ApiReportView.get_report, f"/api/report/{sha256}", 200, [], {"sha256": sha256}),
    pytest.param(
        ApiReportView.get_report_status, f"/api/report/{sha256}/status", 404, [sha256], {},
        marks=pytest.mark.skip(reason="No auth required")
    ),
    pytest.param(
        ApiReportView.get_report_exists, f"/api/report/{sha256}/exists", 404, [sha256], {},
        marks=pytest.mark.skip(reason="No auth required")
    ),
    (ApkView.download_sample, f"/api/apk/{sha256}", 404, [], {"sha256": sha256}),
    (SearchView.search, "/api/search/", 405, [], {}),
])
def test_api_permissions(rf, api_rf, view, url, valid_status, args, kwargs):
    request = api_rf.get(url)
    response = view(request, *args, **kwargs)
    assert response.status_code == valid_status

    request = rf.get(url)
    request.user = AnonymousUser()
    response = view(request, *args, **kwargs)
    assert response.status_code == 401