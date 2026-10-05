import pytest
from unittest.mock import patch

from ..conftest import sha256
from django.conf import settings

from bazaar.core.modules import mobsf


@pytest.mark.slow
@patch("bazaar.core.modules.mobsf.default_storage")
@patch("bazaar.core.modules.mobsf.Elasticsearch.update")
def test_mobsf(mock_es_update, mock_storage):

    with open("/app/tests/_data/test.apk", 'rb') as apk:

        mock_es_update.return_value = True
        mock_storage.open.return_value = apk

        mobsf.analysis(sha256)
        for call in mock_es_update.call_args_list:
            args, kwargs = call

            if kwargs['index'] == settings.ELASTICSEARCH_APK_INDEX:
                doc = kwargs['body']['doc']
                for k in [
                    'analysis_date',
                    'average_cvss',
                    'size',
                    'md5',
                    'sha1',
                    'icon_hidden',
                    'icon_found',
                    'manifest_analysis',
                    'file_analysis',
                    'email_analysis',
                    'secrets',
                    'playstore_details',
                    'url_analysis',
                    'browsable_activities',
                    'detailed_permissions',
                    'android_api_analysis',
                    'code_analysis',
                    'niap_analysis',
                ]:
                    assert k in doc.keys()
