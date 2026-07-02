import pytest
from django.test import RequestFactory
from django.contrib.auth.models import AnonymousUser
from rest_framework.response import Response
from rest_framework.test import APIRequestFactory, force_authenticate

from unittest.mock import Mock, patch
from unittest.mock import call
from io import BytesIO

from bazaar.users.models import User
from bazaar.front.forms import YaraCreateForm
from bazaar.core.models import Yara

from .conftest import sha256, uuid

from bazaar.core.api_view import (
    ReportView,
    ApkView,
)


# Test cases for API Report View
@pytest.mark.django_db
@patch("bazaar.core.api_view.ReportService.list_reports")
def test_list_reports(mock_list_reports, report_list, user: User, rf: RequestFactory):
    request = rf.get("/report/")
    request.user = user

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
    user: User,
    rf: RequestFactory):

    request = rf.get(f"/api/report/{sha256}")
    request.user = user

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
    user: User,
    rf: RequestFactory):

    request = rf.get(f"/api/report/{sha256}/status")
    request.user = user

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
@patch("bazaar.core.api_view.ReportService.get_example")
def test_get_example(
    mock_get_example,
    report_data,
    user: User,
    rf: RequestFactory):

    request = rf.get(f"/api/report/{sha256}/status")
    request.user = user

    mock_get_example.return_value = report_data

    response = ReportView.get_example(request)

    mock_get_example.assert_called_once()
    assert response.status_code == 200
    assert response.data['report'] == report_data


# Test APK API View
@pytest.mark.django_db
@patch("bazaar.core.api_view.ApkView.upload_apk")
@patch("bazaar.core.api_view.ApkView.list_apk")
def test_apk_handler(mock_list, mock_upload, user, rf):
    
    mock_list.return_value = Response()
    mock_upload.return_value = Response()

    request = rf.get('/apk/')
    request.user = user

    response = ApkView.apk_handler(request)
    mock_list.assert_called_once()

    factory = APIRequestFactory()
    request = factory.post("/apk/", {})
    force_authenticate(request, user=user)

    response = ApkView.apk_handler(request)
    mock_upload.assert_called_once()

@pytest.mark.django_db
def test_list_apk(user, rf):
    request = rf.get(f"/apk/")
    request.user = user

    response = ApkView.list_apk(request)
    assert response.status_code == 200

@pytest.mark.django_db
def test_upload_apk(user, rf):
    factory = APIRequestFactory()
    request = factory.post("/apk/", {})
    force_authenticate(request, user=user)

    response = ApkView.upload_apk(request, {})
    assert response.status_code == 200

@pytest.mark.django_db
def test_donwload_apk(user, rf):
    request = rf.get(f"/apk/{sha256}")
    request.user = user

    response = ApkView.download_apk(request, sha256)
    assert response.status_code == 200