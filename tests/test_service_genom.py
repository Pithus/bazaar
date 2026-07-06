import pytest
import copy
from unittest.mock import patch

from .conftest import sha256, uuid

from bazaar.core.services import GenomService


@patch("bazaar.core.services.ReportService.Elasticsearch.search")
def test_genom(mock_search, report_data):

    report1 = copy.deepcopy(report_data)
    report1["andro_cfg"] = {'genom': [1,2,3,4,5,6,7,8,9,10]}
    report2 = copy.deepcopy(report_data)
    report2["sha256"] = f"{"".join(reversed(sha256))}"
    report2["andro_cfg"] = {'genom': [1,2,3,4,5,10,9,8,7,6]}

    mock_search.return_value = {"hits": {"hits": [{"_source": report1}, {"_source": report2}]}}
    
    assert GenomService.get_genom() == [
        f'{sha256}-unknown,{report1["andro_cfg"]["genom"]}',
        f'{"".join(reversed(sha256))}-unknown,{report2["andro_cfg"]["genom"]}'
    ]
