import pytest
from io import BytesIO

from bazaar.users.models import User
from tests.factories import UserFactory
from rest_framework.test import APIRequestFactory, force_authenticate


@pytest.fixture(autouse=True)
def media_storage(settings, tmpdir):
    settings.MEDIA_ROOT = tmpdir.strpath


@pytest.fixture
def user() -> User:
    return UserFactory()


@pytest.fixture
def api_rf(user):
    class ApiRF(APIRequestFactory):
        def __init__(self):
            super().__init__()

        def get(self, path):
            request = super().get(path)
            force_authenticate(request, user=user)
            return request

        def post(self, path, data=None, **kwargs):
            request = super().post(path, data=data, **kwargs)
            force_authenticate(request, user=user)
            return request

    return ApiRF()


# Test Data
sha256 = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
uuid = 'fa9c0834-7f94-474a-88d2-25e0f936d71c'


@pytest.fixture
def report_data():
    yield {
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
        "dexofuzzy": {
            "apk": [],
        },
    }


@pytest.fixture
def detailed_status():
    yield {
        "apkid_analysis": 2,
        "ssdeep_analysis": 2,
        "extract_classes": 2,
        "quark_analysis": 2,
        "analysis_date": "2026-06-24T20:10:00.000000",
        "vt_analysis": 2,
        "malware_bazaar_analysis": 2,
        "mobsf_analysis": 2
    }


@pytest.fixture
def report_status():
    yield {
        "in_error": False,
        "success": True,
        "analysis_launched": True,
        "running": False
    }


@pytest.fixture
def yara_rule():
    yield {
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


@pytest.fixture
def report_list():
    yield [
        {
            "handle": "com.example.app",
            "apk_hash": "c031952608a4374ef94ea1ae12b42116aaa03b4b3a005ff9c578e181876692a0"
        },
        {
            "handle": "com.android.example.app",
            "apk_hash": "97532c13352c91b1fc558da6fe4e918373dc1420eefbdb11ea51c91a6a6a3817"
        },
        {
            "handle": "com.test.app.custom",
            "apk_hash": "c886a5311950247f46c8348765113b8d113505ceff6b52ae91e4e7547bc4a26e"
        },
    ]


@pytest.fixture
def fake_apk():
    class FakeApk(BytesIO):
        def __init__(self, content: bytes, name='test.apk'):
            super().__init__(content)
            self.size = len(content)
            self.name = name
            self.content = content

        def chunks(self, size=10):
            while len(self.content) > 0:
                content = self.content[:size]
                self.content = self.content[size:]
                yield content
    return FakeApk(b"test")
