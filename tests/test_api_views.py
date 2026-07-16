import pytest
from django.test import RequestFactory
from django.contrib.auth.models import AnonymousUser
from django.core.files.uploadedfile import SimpleUploadedFile

from rest_framework.response import Response
from rest_framework.test import APIRequestFactory, force_authenticate

from unittest.mock import patch
from unittest.mock import call
from io import BytesIO

from bazaar.users.models import User
from bazaar.front.forms import YaraCreateForm
from bazaar.core.models import Yara

from .conftest import sha256, uuid

from bazaar.core.api_view import (
    ReportView,
    ApkView,
    SearchView,
)


# Test cases for API Report View
@pytest.mark.django_db
@patch("bazaar.core.api_view.ReportService.list_reports")
def test_list_reports(mock_list_reports, report_list, api_rf):
    request = api_rf.get("/report/")
    mock_list_reports.return_value = report_list

    response = ReportView.list_reports(request)
    assert response.status_code == 200
    assert response.data["reports"] == report_list

@pytest.mark.django_db
@patch("bazaar.core.api_view.ReportService.get_status")
@patch("bazaar.core.api_view.ReportService.get_report")
def test_get_report(
    mock_get_report,
    mock_get_status,
    report_data,
    report_status,
    api_rf):

    request = api_rf.get(f"/api/report/{sha256}")

    mock_get_report.return_value = report_data
    mock_get_status.return_value = report_status

    response = ReportView.get_report(
        request,
        sha256=f"{sha256}",
    )

    assert mock_get_report.call_args_list == [
        call(sha256)
    ]
    assert response.status_code == 200
    assert response.data['report'] == report_data

@pytest.mark.django_db
@patch("bazaar.core.api_view.ReportService.get_status")
@patch("bazaar.core.api_view.ReportService.get_detailed_status")
def test_get_status(
    mock_get_detailed_status,
    mock_get_status,
    report_status,
    detailed_status,
    api_rf):

    request = api_rf.get(f"/api/report/{sha256}/status")

    mock_get_status.return_value = report_status
    mock_get_detailed_status.return_value = detailed_status

    response = ReportView.get_report_status(
        request,
        sha256=f"{sha256}",
    )

    assert mock_get_status.call_args_list == [
        call(sha256)
    ]
    assert response.status_code == 200
    assert response.data['report_status'] == report_status
    assert response.data['detailed_status'] == detailed_status

@pytest.mark.django_db
def test_exists_fail(api_rf):
    request = api_rf.get(f"/report/{sha256}/exists")

    response = ReportView.get_report_exists(request, sha256)
    assert response.status_code == 404

@pytest.mark.django_db
@patch("bazaar.core.api_view.default_storage.exists")
def test_exists_fail(mock_exists, api_rf):
    request = api_rf.get(f"/report/{sha256}/exists")

    mock_exists.return_value = True
    response = ReportView.get_report_exists(request, sha256)
    assert response.status_code == 200

@pytest.mark.django_db
@patch("bazaar.core.api_view.ReportService.get_example")
def test_get_example(
    mock_get_example,
    report_data,
    api_rf):

    request = api_rf.get(f"/api/report/{sha256}/status")
    mock_get_example.return_value = report_data

    response = ReportView.get_example(request)
    mock_get_example.assert_called_once()
    assert response.status_code == 200
    assert response.data['report'] == report_data


# Test APK API View
@pytest.mark.django_db
@patch("bazaar.core.api_view.ApkView.upload_apk")
@patch("bazaar.core.api_view.ApkView.list_apk")
def test_apk_handler(mock_list, mock_upload, api_rf):
    mock_list.return_value = Response()
    mock_upload.return_value = Response()

    request = api_rf.get('/apk/')
    response = ApkView.apk_handler(request)
    mock_list.assert_called_once()

    request = api_rf.post("/apk/", {})
    response = ApkView.apk_handler(request)
    mock_upload.assert_called_once()

@pytest.mark.django_db
def test_list_apk(api_rf):
    request = api_rf.get(f"/apk/")

    response = ApkView.list_apk(request)
    assert response.status_code == 501

@pytest.mark.django_db
@patch("bazaar.core.api_view.ApkService.upload_apk")
def test_upload_apk(
    mock_service_upload,
    api_rf):

    apk_data = SimpleUploadedFile("test.apk", b"filecontent")
    mock_service_upload.return_value = sha256

    request = api_rf.post("/apk/", {"apk": apk_data})

    response = ApkView.upload_apk(request)
    assert response.status_code == 200
    assert response.data == {"message": "OK", "file_hash": f"{sha256}"}

@pytest.mark.django_db
def test_download_apk_not_found(api_rf):
    request = api_rf.get(f"/apk/{sha256}")

    response = ApkView.download_sample(request, sha256)
    assert response.status_code == 404

@pytest.mark.django_db
@patch("bazaar.core.services.ApkService.sample_exists")
@patch("bazaar.core.services.ApkService.download_sample")
def test_download_apk(mock_dl, mock_exists, api_rf):
    request = api_rf.get(f"/apk/{sha256}")

    apk_content = b'test file content'
    mock_dl.return_value = BytesIO(apk_content)
    mock_exists.return_value = True

    response = ApkView.download_sample(request, sha256)
    assert response.status_code == 200
    assert b''.join(response.streaming_content) == apk_content


# Test Search API View
@pytest.mark.django_db
@patch("bazaar.core.api_view.SearchService.search")
def test_search(mock_search, report_data, api_rf):
    request = api_rf.post(f"/search/", {"q": f"sha256:{sha256}"})

    mock_search.return_value = report_data
    response = SearchView.search(request)
    assert response.status_code ==  200
    assert response.data == {"result": report_data, "message": "OK"}