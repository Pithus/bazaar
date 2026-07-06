import os
import pytest
from unittest.mock import patch, Mock, call

from ..conftest import sha256, uuid
from django.conf import settings

from bazaar.core.modules import quarkengine

@pytest.mark.slow
@patch("bazaar.core.modules.quarkengine.run_freshquark")
@patch("bazaar.core.modules.quarkengine.default_storage")
@patch("bazaar.core.modules.quarkengine.Elasticsearch.update")
def test_quarkengine(mock_es_update, mock_storage, mock_freshquark):

    mock_freshquark.return_value = True
    with open("/app/tests/_data/test.apk", 'rb') as apk:

        mock_es_update.return_value = True
        mock_storage.open.return_value = apk
        quarkengine.analysis(sha256)

        for call in mock_es_update.call_args_list:
            args, kwargs = call

            if kwargs['index'] == settings.ELASTICSEARCH_APK_INDEX:
                quark = kwargs['body']['doc']['quark']
                for k in [
                    'md5',
                    'apk_filename',
                    'size_bytes',
                    'threat_level',
                    'crimes',
                ]:
                    assert k in quark.keys()