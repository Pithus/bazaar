import pytest
from django.test import RequestFactory
from django.core.files.uploadedfile import SimpleUploadedFile
from django.contrib.auth.models import AnonymousUser
from django.contrib.messages.storage.fallback import FallbackStorage
from django.utils import timezone

from unittest.mock import Mock, patch
from unittest.mock import call
from io import BytesIO

from bazaar.users.models import User
from bazaar.front.forms import YaraCreateForm
from bazaar.core.models import Yara

from .conftest import sha256, uuid

from bazaar.front.view import (
    HomeView,
    ReportView,
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
)


# Test cases for Home View
def test_get(self, rf: RequestFactory):
    view = HomeView()
    request = rf.get("/")

    assert view.get(request).status_code == 200


# Test cases for Report View
def test_get(rf: RequestFactory):
    view = ReportView()
    request = rf.get("/report/")

    response = view.get(request)
    assert response.status_code == 302
    assert response.url == "/"

@pytest.mark.django_db
@patch("bazaar.front.view.ReportService.get_status")
@patch("bazaar.front.view.ReportService.get_report")
@patch("bazaar.front.view.Elasticsearch.get")
def test_get_report(
    mock_es_get,
    mock_get_report,
    mock_get_status,
    report_data,
    report_status,
    user: User,
    rf: RequestFactory):

    request = rf.get(f"/report/{sha256}")
    request.user = user

    mock_get_report.return_value = report_data
    mock_get_status.return_value = report_status
    mock_es_get.return_value = {"_source": report_data}

    response = ReportView.as_view()(
        request,
        sha256=f"{sha256}",
    )

    assert mock_get_report.call_args_list == [
        call(sha256),
    ]
    assert response.status_code == 200


# Test cases for basic_url_download
@pytest.mark.django_db
def test_basic_url_download_redirect(user: User, rf: RequestFactory):
    request = rf.get('/url/')
    request.user = user

    response = basic_url_download_view(request)
    assert response.status_code == 302
    assert response.url == "/"

@pytest.mark.django_db
@patch("bazaar.front.view.ApkService.upload_apk")
@patch("bazaar.front.view.requests.get")
def test_basic_url_download_ok(
    mock_get,
    mock_service_upload,
    fake_apk,
    user: User,
    rf: RequestFactory
):
    request = rf.post(f"/url/", data={"url": f"https://127.0.0.1/test.apk"})
    request.user = user

    response_mock = Mock()
    response_mock.status_code = 200
    response_mock.raw = fake_apk
    mock_get.return_value = response_mock
    mock_service_upload.return_value = sha256

    response = basic_url_download_view(request)
    assert response.status_code == 302
    assert response.url == f"/report/{sha256}"


# Test cases for basic_url_download
@pytest.mark.django_db
def test_basic_upload_view_get(user: User, rf: RequestFactory):
    request = rf.get('/apk/')
    request.user = user

    response = basic_upload_view(request)
    assert response.status_code == 302
    assert response.url == "/"

@pytest.mark.django_db
@patch("bazaar.core.api_view.ApkService.upload_apk")
def test_basic_upload_view_post(
    mock_service_upload,
    user: User,
    rf: RequestFactory
):
    mock_file = SimpleUploadedFile("test.apk", b"filecontent")

    request = rf.post(f"/apk/", {"apk": mock_file})
    request.user = user
    mock_service_upload.return_value = sha256

    response = basic_upload_view(request)
    assert response.status_code == 302
    assert response.url == f"/report/{sha256}"


# Test Similarity View
@pytest.mark.django_db
def test_similarity_search_view(user: User, rf: RequestFactory):
    request = rf.get("/similar/")
    request.user = user

    response = similarity_search_view(request, sha256=sha256)
    assert response.status_code == 200


# Test Sample Download
def test_download_sample_view_unauth(rf: RequestFactory):
    request = rf.get(f"/apk/{sha256}")
    request.user = AnonymousUser()

    response = download_sample_view(request, sha256=sha256)

    assert response.status_code == 302
    assert response.url == "/"

@pytest.mark.django_db
@patch("bazaar.front.view.default_storage.exists")
@patch("bazaar.front.view.default_storage.open")
def test_download_sample_view(mock_open, mock_exists, user: User, rf: RequestFactory):
    request = rf.get(f"/apk/{sha256}")
    request.user = user

    mock_open.return_value = BytesIO(b"filecontent")
    mock_exists.return_value = True

    response = download_sample_view(request, sha256=sha256)
    assert response.status_code == 200
    assert response.content == b"filecontent"


# Test Export Report
def test_export_report_unauth(rf: RequestFactory):
    request = rf.get(f"/report/{sha256}/json")
    request.user =  AnonymousUser()

    response = export_report_view(request, sha256)
    assert response.status_code == 302
    assert response.url == "/"

@pytest.mark.django_db
@patch("bazaar.front.view.Elasticsearch.get")
def test_export_report_view(mock_es_get, user: User, rf: RequestFactory):
    request = rf.get(f"/report/{sha256}/json")
    request.user = user

    mock_es_get.return_value = {"_source":
        {"json": "value"}
    }

    response = export_report_view(request, sha256)
    assert response.status_code == 200
    assert response.content == b'{"json": "value"}'


# Test OGCard
@patch("bazaar.front.view.Elasticsearch.get")
def test_og_card_view(mock_es_get, report_data, rf: RequestFactory):
    request = rf.get(f"/report/{sha256}/card")

    mock_es_get.return_value = {"_source": report_data}
    response = og_card_view(request, sha256)

    assert response.status_code == 200
    assert response.headers['content-type'] == "image/png"


# Test Rules
def  test_my_rules_view_unauth(rf: RequestFactory):
    request = rf.get("/rules/")
    request.user = AnonymousUser()

    response = my_rules_view(request)
    assert response.status_code == 302
    assert response.url == "/"

@pytest.mark.django_db
def  test_my_rules_view(user: User, rf: RequestFactory):
    request = rf.get("/rules/")
    request.user = user

    response = my_rules_view(request)
    assert response.status_code == 200

def test_my_rule_create_view_unauth(rf: RequestFactory):
    request = rf.post("/rules/")
    request.user = AnonymousUser()

    response = my_rule_create_view(request)
    assert response.status_code == 302
    assert response.url == "/"

@pytest.mark.django_db
def test_my_rule_create_view(yara_rule, user: User, rf: RequestFactory):
    request = rf.post("/rules/", yara_rule)
    request.user = user
    request.session = {}
    messages = FallbackStorage(request)
    setattr(request, "_messages", messages)

    response = my_rule_create_view(request)

    assert response.status_code == 302
    assert response.url == "/rules/"

def test_my_rule_edit_view_unauth(rf: RequestFactory):
    request = rf.get("/rules/")
    request.user = AnonymousUser()

    response = my_rule_edit_view(request, None)
    assert response.status_code == 302
    assert response.url == "/"

@pytest.mark.django_db
@patch("bazaar.front.view.Yara.objects.get")
def test_my_rule_edit_view_get(mock_yara_get, user: User, rf: RequestFactory):
    request = rf.get(f"/rules/{uuid}")
    request.user = user

    rule = Yara(
        id=uuid,
        title="test",
        content="rule TestYaraRule {condition: true}",
        is_private=True,
        owner=request.user,
    )
    mock_yara_get.return_value = rule

    response = my_rule_edit_view(request, uuid)
    assert response.status_code == 200
    assert b"rule TestYaraRule {condition: true}" in response.content

@pytest.mark.django_db
@patch("bazaar.front.view.Yara.objects.get")
@patch("bazaar.core.services.rules.delete_es_matches")
def test_my_rule_edit_view_post(mock_es_delete, mock_yara_get, yara_rule, user: User, rf: RequestFactory):
    request = rf.post(f"/rules/{uuid}", yara_rule)
    request.user = user
    request.session = {}
    messages = FallbackStorage(request)
    setattr(request, "_messages", messages)

    rule = Yara(
        id=uuid,
        title="yara-test-rule",
        content="rule TestYaraRule {condition: true}",
        is_private=True,
        owner=request.user,
    )
    mock_yara_get.return_value = rule
    mock_es_delete.return_value = True

    response = my_rule_edit_view(request, uuid)
    assert response.status_code == 302
    assert response.url == '/rules/'

def test_my_rule_delete_view_unauth(rf: RequestFactory):
    request = rf.get(f"/rules/{uuid}/delete")
    request.user = AnonymousUser()

    response = my_rule_delete_view(request, uuid)
    assert response.status_code == 302
    assert response.url == '/'

@pytest.mark.django_db
@patch("bazaar.front.view.Yara.objects.get")
@patch("bazaar.front.view.Yara.delete")
@patch("bazaar.core.services.rules.delete_es_matches")
def test_my_rule_delete_view(mock_es_delete, mock_yara_delete, mock_yara_get, user: User, rf: RequestFactory):
    request = rf.get(f"/rules/{uuid}/delete")
    request.user = user
    request.session = {}
    messages = FallbackStorage(request)
    setattr(request, "_messages", messages)

    rule = Yara(
        id=uuid,
        title="yara-test-rule",
        content="rule TestYaraRule {condition: true}",
        is_private=True,
        owner=request.user,
    )
    mock_yara_get.return_value = rule
    mock_es_delete.return_value = True
    mock_yara_delete.return_value = True

    response = my_rule_delete_view(request, uuid)
    assert mock_yara_delete.call_count == 1
    assert response.status_code == 302
    assert response.url == '/rules/'

def test_my_retrohunt_view_unauth(rf: RequestFactory):
    request = rf.get(f"/rules/{uuid}/retro")
    request.user = AnonymousUser()
    request.session = {}
    messages = FallbackStorage(request)
    setattr(request, "_messages", messages)

    response = my_retrohunt_view(request, uuid)
    assert response.status_code == 302
    assert response.url == '/'

@pytest.mark.django_db
@patch("bazaar.front.view.messages.success")
@patch("bazaar.front.view.async_task")
def test_my_retrohunt_view(mock_async, mock_messages, user: User, rf: RequestFactory):
    request = rf.get(f"/rules/{uuid}/retro")
    request.user = user

    mock_async.return_value = True
    mock_messages.return_value = True

    response = my_retrohunt_view(request, uuid)
    assert mock_messages.call_count == 1
    assert response.status_code == 302
    assert response.url == '/rules/'
