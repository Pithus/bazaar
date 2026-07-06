import os
import pytest
from unittest.mock import patch, Mock, call

from ..conftest import sha256, uuid

from bazaar.core.modules import apkid

@patch("bazaar.core.modules.apkid.default_storage")
@patch("bazaar.core.modules.apkid.Elasticsearch.update")
def test_apkid(mock_es_update, mock_storage):

    with open("/app/tests/_data/test.apk", 'rb') as apk:

        mock_es_update.return_value = True
        mock_storage.open.return_value = apk

        apkid.analysis(sha256)
        results = 0
        for call in mock_es_update.call_args_list:
            args, kwargs = call

            try:
                for finding in kwargs['body']['doc']['apkid']:
                    for k in [
                        'filename',
                        'matches',
                    ]:
                        assert k in finding.keys()
                        results += 1
            except KeyError:
                pass

        assert results > 0