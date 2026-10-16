from unittest.mock import patch
from ..conftest import sha256
from bazaar.core.modules import misp


@patch("bazaar.core.modules.misp.pymisp.PyMISP.search")
@patch("bazaar.core.modules.misp.pymisp.PyMISP")
@patch("bazaar.core.modules.misp.ReportService.get_report")
@patch("bazaar.core.modules.misp.Elasticsearch.update")
@patch("bazaar.core.modules.misp.Elasticsearch.get")
def test_misp(mock_es_get, mock_es_update, mock_get_report, mock_pymisp, mock_search, report_data):

    mock_es_get.return_value = {"_source": {"mobsf_analysis": 2}}
    mock_es_update.return_value = True
    mock_get_report.return_value = report_data
    mock_search.return_value = {
        'Attribute': [
            {
                'id': '1234',
                'event_id': '4321',
                'category': 'Payload delivery',
                'type': 'sha256',
                'to_ids': False,
                'uuid': 'b184f93f-4fa8-d7c2-8afb-234c190e3670',
                'timestamp': '1792137006',
                'distribution': '5',
                'comment': '',
                'sharing_group_id': '0',
                'deleted': False,
                'disable_correlation': False,
                'object_id': '0',
                'object_relation': None,
                'first_seen': None,
                'last_seen': None,
                'value': f'{sha256}',
                'event_uuid': 'b184f93f-4fa8-d7c2-8afb-234c190e3670',
                'Event': {
                    'id': '84126',
                    'orgc_id': '95',
                    'org_id': '95',
                    'date': '2026-10-16',
                    'threat_level_id': '4',
                    'info': 'test event',
                    'published': True,
                    'uuid': 'b184f93f-4fa8-d7c2-8afb-234c190e3670',
                    'analysis': '0',
                    'timestamp': '1792137067',
                    'distribution': '1',
                    'publish_timestamp': '1792137096',
                    'sharing_group_id': '0',
                    'extends_uuid': '',
                    'Tag': [],
                    'Orgc': {'id': '95', 'name': 'OrgName', 'uuid': 'b184f93f-4fa8-d7c2-8afb-234c190e3670'},
                    'Org': {'id': '95', 'name': 'OrgName', 'uuid': 'b184f93f-4fa8-d7c2-8afb-234c190e3670'},
                    'ThreatLevel': ''
                }
            }
        ]
    }

    mock_pymisp.return_value = True

    matches = {
        f'{sha256}:4321': {
            "ioc": f'{sha256}',
            "event_id": '4321',
            "event_info": 'test event',
            "event_url": "/events/view/4321"
        }
    }

    misp.analysis(sha256)
    for call in mock_es_update.call_args_list:
        args, kwargs = call

        if kwargs["body"]["doc"].get("misp_analysis", None) is not None:
            continue

        assert kwargs["body"] == {
            'doc': {'misp_matches': matches}
        }

    assert len(mock_es_update.call_args_list) == 1
