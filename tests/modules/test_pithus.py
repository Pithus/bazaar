import pytest
from unittest.mock import patch

from ..conftest import sha256
from django.conf import settings

from bazaar.core.modules import pithus


@pytest.mark.parametrize("function, doc_key, result_keys", [
    (pithus.extract_ioc, 'iocs', ['urls_list', 'url_nf', 'emails_nf', 'secrets',]),
    pytest.param(pithus.extract_attributes, None, [
        'sha256', 'handle', 'app_name', 'uaid', 'version_name', 'version_code',
        'icon_hash', 'apk_hash', 'icon_base64', 'sha1', 'md5', 'certificates',
        'uploaded_at', 'sha256', 'activities', 'features', 'libraries', 'main_activity',
        'min_sdk_version', 'max_sdk_version', 'target_sdk_version', 'permissions',
        'aosp_permissions', 'third_party_permissions', 'providers', 'receivers',
        'services', 'is_valid', 'is_signed', 'is_signed_v1', 'is_signed_v2', 'is_signed_v3'
    ], marks=pytest.mark.slow),
    (pithus.frosting_analysis, 'frosting_data', ['is_frosted', 'v2_signature_blocks']),
])
@patch("bazaar.core.modules.pithus.default_storage")
@patch("bazaar.core.modules.pithus.Elasticsearch.update")
@patch("bazaar.core.modules.pithus.Elasticsearch.exists")
def test_pithus(mock_es_exists, mock_es_update, mock_storage, function, doc_key, result_keys):

    result = 0
    with open("/app/tests/_data/test.apk", 'rb') as apk:

        mock_es_exists.return_value = True
        mock_es_update.return_value = True
        mock_storage.open.return_value = apk
        function(sha256)

        for call in mock_es_update.call_args_list:
            args, kwargs = call

            if kwargs['index'] == settings.ELASTICSEARCH_APK_INDEX:
                doc = kwargs['body']['doc']
                if doc_key is not None:
                    doc = kwargs['body']['doc'][doc_key]
                for k in result_keys:
                    assert k in doc.keys()
                    result += 1

    assert result > 0


@pytest.mark.slow
@patch("bazaar.core.modules.pithus.default_storage")
@patch("bazaar.core.modules.pithus.Elasticsearch.update")
@patch("bazaar.core.modules.pithus.Elasticsearch.exists")
def test_extract_classes(mock_es_exists, mock_es_update, mock_storage):

    result = 0
    with open("/app/tests/_data/test.apk", 'rb') as apk:

        mock_es_exists.return_value = True
        mock_es_update.return_value = True
        mock_storage.open.return_value = apk

        pithus.extract_classes(sha256)

        for call in mock_es_update.call_args_list:
            args, kwargs = call

            if kwargs['index'] == settings.ELASTICSEARCH_APK_INDEX:
                if 'java_classes' in kwargs['body']['doc'] or 'trackers' in kwargs['body']['doc']:
                    result += 1

    assert result == 2
