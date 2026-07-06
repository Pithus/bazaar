import os
import pytest
from unittest.mock import patch, Mock, call

from ..conftest import sha256, uuid
from django.conf import settings

from bazaar.core.modules import similarity

@patch("bazaar.core.modules.similarity.default_storage")
@patch("bazaar.core.modules.similarity.Elasticsearch.update")
def test_similarity(mock_es_update, mock_storage):

    with open("/app/tests/_data/test.apk", 'rb') as apk:

        mock_es_update.return_value = True
        mock_storage.open.return_value = apk

        similarity.analysis(sha256)

        for call in mock_es_update.call_args_list:
            args, kwargs = call

            if kwargs['index'] == settings.ELASTICSEARCH_APK_INDEX:
                doc = kwargs['body']['doc']
                for k in [
                    'ssdeep',
                    'dexofuzzy',
                ]:
                    assert k in doc.keys()