from unittest.mock import patch

from ..conftest import sha256
from django.conf import settings

from bazaar.core.modules import virus_total


@patch("bazaar.core.modules.virus_total.Elasticsearch.update")
def test_virus_total(mock_es_update):

    result = 0
    mock_es_update.return_value = True

    virus_total.analysis(sha256)

    for call in mock_es_update.call_args_list:
        args, kwargs = call

        if kwargs['index'] == settings.ELASTICSEARCH_APK_INDEX:
            doc = kwargs['body']['doc']['vt_report']
            for k in [
                'id',
                'type',
                'attributes',
                'links',
            ]:
                assert k in doc.keys()
                result += 1
    assert result > 0
