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

# Test data
sha256 = "f2ca1bb6c7e907d06dafe4687e579fce76b37e4e93b7605022da52e6ccc26fd2"
uuid = 'fa9c0834-7f94-474a-88d2-25e0f936d71c'

report_data = {"_source": {
        "handle": "com.app.test",
        "app_name": "app_test",
        "uaid": "4e1243bd22c66e76c2ba9eddc1f91394e57f9f83",
        "version_name": "1.0",
        "version_code": 1,
        "icon_hash": None,
        "apk_hash": "4e1243bd22c66e76c2ba9eddc1f91394e57f9f83",
        "icon_base64": None,
        "sha1": "4e1243bd22c66e76c2ba9eddc1f91394e57f9f83",
        "md5": "d8e8fca2dc0f896fd7cb4cb0031ba249",
        "certificates": [
        ],
        "uploaded_at": "2026-06-24T20:10:00.000000",
        "sha256": f"{sha256}",
        "permissions": [],
        "activities": [],
        "services": [],
        "receivers": [],
        "domains_analysis": [],
    }
}

status = {
    "_source": {
            "apkid_analysis": 2,
            "ssdeep_analysis": 2,
            "extract_classes": 2,
            "quark_analysis": 2,
            "analysis_date": "2026-06-24T20:10:00.000000",
            "vt_analysis": 2,
            "malware_bazaar_analysis": 2,
            "mobsf_analysis": 2
        }
}

yara_rule = {
    "title": "yara-test-rule",
    "content": """rule TestRule
        {
            strings:
                $my_text_string = "text here"
                $my_hex_string = { E2 34 A1 C8 23 FB }

            condition:
                $my_text_string or $my_hex_string
        }
    """,
    "is_private": True
}

class TestHomeView:
    """ Test cases for Home View """

    def test_get(self, rf: RequestFactory):
        view = HomeView()
        request = rf.get("/")

        assert view.get(request).status_code == 200


class TestReportView:
    """ Test cases for Report View """

    def test_get(self, rf: RequestFactory):
        view = ReportView()
        request = rf.get("/report/")

        response = view.get(request)
        assert response.status_code == 302
        assert response.url == "/"

    @pytest.mark.django_db
    @patch("bazaar.front.view.Elasticsearch.get")
    def test_get_report(self, mock_es_get, user: User, rf: RequestFactory):

        def fake_fetch_es(*args, **kwargs):
            index = kwargs["index"]
            if index == "apk_analysis":
                return report_data
            elif index == "analysis_tasks":
                return status
            raise ValueError(f"Unexpected argument: {index}")

        mock_es_get.side_effect = fake_fetch_es
        request = rf.get(f"/report/{sha256}")
        request.user = user

        response = ReportView.as_view()(
            request,
            sha256=f"{sha256}",
        )

        assert mock_es_get.call_args_list == [
            call(index="apk_analysis", id=f"{sha256}"),
            call(index="analysis_tasks", id=f"{sha256}"),
            call(index="apk_analysis", id=f"{sha256}"), # From get_timeline()
        ]
        assert response.status_code == 200

class TestBasicUrlDownloadView:
    """ Test cases for basic_url_download """

    @pytest.mark.django_db
    def test_basic_url_download_redirect(self, user: User, rf: RequestFactory):
        request = rf.get('/url/')
        request.user = user
        
        response = basic_url_download_view(request)
        assert response.status_code == 302
        assert response.url == "/"

    @pytest.mark.django_db
    @patch("bazaar.front.view.default_storage.exists")
    @patch("bazaar.front.view.requests.get")
    @patch("bazaar.front.view.is_android")
    def test_basic_url_download_redirect(
        self,
        mock_is_android,
        mock_requests_get,
        mock_exists,
        user: User,
        rf: RequestFactory
    ):
        request = rf.post(f"/url/", data={"url": f"https://127.0.0.1/test.apk"})
        request.user = user

        response_mock = Mock()
        response_mock.status_code = 200
        response_mock.iter_content.return_value = [b"file", b"content"]

        mock_requests_get.return_value = response_mock
        mock_is_android.return_value =  "APK"
        mock_exists.return_value = True

        response = basic_url_download_view(request)
        assert response.status_code == 302
        assert response.url == "/report/5ab24eb0866bafe7d8c0d07f03f09aef7a4caa991a9dc1edd96e64683b750fe2"


class TestBasicUploadView:
    """ Test cases for basic_url_download """

    @pytest.mark.django_db
    def test_basic_upload_view(self, user: User, rf: RequestFactory):
        request = rf.get('/apk/')
        request.user = user
        
        response = basic_upload_view(request)
        assert response.status_code == 302
        assert response.url == "/"

    @pytest.mark.django_db
    @patch("bazaar.front.view.default_storage.exists")
    @patch("bazaar.front.view.requests.get")
    @patch("bazaar.front.view.is_android")
    def test_basic_upload(
        self,
        mock_is_android,
        mock_requests_get,
        mock_exists,
        user: User,
        rf: RequestFactory
    ):
    
        mock_file = SimpleUploadedFile("test.apk", b"filecontent")

        request = rf.post(f"/apk/", {"apk": mock_file})
        request.user = user

        response_mock = Mock()
        response_mock.status_code = 200

        mock_requests_get.return_value = response_mock
        mock_is_android.return_value =  "APK"
        mock_exists.return_value = True

        response = basic_upload_view(request)
        assert response.status_code == 302
        assert response.url == "/report/5ab24eb0866bafe7d8c0d07f03f09aef7a4caa991a9dc1edd96e64683b750fe2"


class TestSimilaritySearchView:

    @pytest.mark.django_db
    def test_similarity_search_view(self, user: User, rf: RequestFactory):
        request = rf.get("/similar/")
        request.user = user
        
        response = similarity_search_view(request, sha256=sha256)
        assert response.status_code == 200


class TestDownloadSample:

    def test_download_sample_view_unauth(self, rf: RequestFactory):
        request = rf.get(f"/apk/{sha256}")
        request.user = AnonymousUser()

        response = download_sample_view(request, sha256=sha256)

        assert response.status_code == 302
        assert response.url == "/"

    @pytest.mark.django_db
    @patch("bazaar.front.view.default_storage.exists")
    @patch("bazaar.front.view.default_storage.open")
    def test_download_sample_view(self, mock_open, mock_exists, user: User, rf: RequestFactory):
        request = rf.get(f"/apk/{sha256}")
        request.user = user

        mock_open.return_value = BytesIO(b"filecontent")
        mock_exists.return_value = True

        response = download_sample_view(request, sha256=sha256)
        assert response.status_code == 200
        assert response.content == b"filecontent"


class TestExportReportView:

    def test_export_report_unauth(self, rf: RequestFactory):
        request = rf.get(f"/report/{sha256}/json")
        request.user =  AnonymousUser()

        response = export_report_view(request, sha256)
        assert response.status_code == 302
        assert response.url == "/"

    @pytest.mark.django_db
    @patch("bazaar.front.view.Elasticsearch.get")
    def test_export_report_view(self, mock_es_get, user: User, rf: RequestFactory):
        request = rf.get(f"/report/{sha256}/json")
        request.user = user

        mock_es_get.return_value = {"_source":
            {"json": "value"}
        }

        response = export_report_view(request, sha256)
        assert response.status_code == 200
        assert response.content == b'{"json": "value"}'


class TestOgCardView:

    @patch("bazaar.front.view.Elasticsearch.get")
    def test_og_card_view(self, mock_es_get, rf: RequestFactory):
        request = rf.get(f"/report/{sha256}/card")

        mock_es_get.return_value = report_data
        response = og_card_view(request, sha256)

        assert response.status_code == 200
        assert response.headers['content-type'] == "image/png"


class TestMyRules:

    def  test_my_rules_view_unauth(self, rf: RequestFactory):
        request = rf.get("/rules/")
        request.user = AnonymousUser()

        response = my_rules_view(request)
        assert response.status_code == 302
        assert response.url == "/"

    @pytest.mark.django_db
    def  test_my_rules_view(self, user: User, rf: RequestFactory):
        request = rf.get("/rules/")
        request.user = user

        response = my_rules_view(request)
        assert response.status_code == 200
    
    def test_my_rule_create_view_unauth(self, rf: RequestFactory):
        request = rf.post("/rules/")
        request.user = AnonymousUser()

        response = my_rule_create_view(request)
        assert response.status_code == 302
        assert response.url == "/"

    @pytest.mark.django_db
    def test_my_rule_create_view(self,  user: User, rf: RequestFactory):
        request = rf.post("/rules/", yara_rule)
        request.user = user
        request.session = {}
        messages = FallbackStorage(request)
        setattr(request, "_messages", messages)

        response = my_rule_create_view(request)

        assert response.status_code == 302
        assert response.url == "/rules/"

    def  test_my_rule_edit_view_unauth(self, rf: RequestFactory):
        request = rf.get("/rules/")
        request.user = AnonymousUser()

        response = my_rule_edit_view(request, None)
        assert response.status_code == 302
        assert response.url == "/"

    @pytest.mark.django_db
    @patch("bazaar.front.view.Yara.objects.get")
    def  test_my_rule_edit_view_get(self, mock_yara_get, user: User, rf: RequestFactory):
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
    @patch("bazaar.front.view.delete_es_matches")
    def  test_my_rule_edit_view_post(self, mock_es_delete, mock_yara_get, user: User, rf: RequestFactory):
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

    def test_my_rule_delete_view_unauth(self, rf: RequestFactory):
        request = rf.get(f"/rules/{uuid}/delete")
        request.user = AnonymousUser()

        response = my_rule_delete_view(request, uuid)
        assert response.status_code == 302
        assert response.url == '/'

    @pytest.mark.django_db
    @patch("bazaar.front.view.Yara.objects.get")
    @patch("bazaar.front.view.Yara.delete")
    @patch("bazaar.front.view.delete_es_matches")
    def test_my_rule_delete_view(self, mock_es_delete, mock_yara_delete, mock_yara_get, user: User, rf: RequestFactory):
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

    def test_my_retrohunt_view_unauth(self, rf: RequestFactory):
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
    def test_my_retrohunt_view(self, mock_messages, user: User, rf: RequestFactory):
        request = rf.get(f"/rules/{uuid}/retro")
        request.user = user

        mock_messages.return_value = True

        response = my_retrohunt_view(request, uuid)
        assert mock_messages.call_count == 1
        assert response.status_code == 302
        assert response.url == '/rules/'
