import os
import pytest
from unittest.mock import patch, Mock, call

from ..conftest import sha256, uuid

from django.core.files import File
from bazaar.core.modules import androcfg

@pytest.mark.slow
@patch("bazaar.core.modules.androcfg.default_storage")
@patch("bazaar.core.modules.androcfg.Elasticsearch.update")
@patch("bazaar.core.modules.androcfg.Elasticsearch.get")
def test_androcfg(mock_es_get, mock_es_update, mock_storage, report_data):

    with open("/app/tests/_data/test.apk", 'rb') as apk:

        
        mock_storage.size.return_value = 1024
        mock_storage.open.return_value = apk
        mock_storage.save.return_value = True

        mock_es_get.return_value = {"_source": {"andro_cfg": None}}
        mock_es_update.return_value = True

        androcfg.analysis(sha256)
        for call in mock_storage.save.call_args_list:
            args, kwargs = call
            filename, picture = args

            assert filename.startswith(f"andro_cfg_{sha256}")
            assert isinstance(picture, File)

        assert len(mock_storage.save.call_args_list) == 94
