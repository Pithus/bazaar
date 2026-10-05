import pytest
from unittest.mock import patch, Mock

from ..conftest import sha256

from bazaar.core.services import RulesService


@pytest.mark.django_db
@patch("bazaar.core.services.rules.Elasticsearch.search")
@patch("bazaar.core.services.rules.Yara")
@patch("bazaar.core.services.rules.SearchService.light_sample_search")
def test_get_rules(mock_light_search, mock_yara, mock_es_search, user):

    rule1 = Mock()
    rule1.id = "rule id 1"
    rule1.is_private = True
    rule1.__eq__ = lambda a, b: a.id == b

    rule2 = Mock()
    rule2.id = "rule id 2"
    rule2.is_private = False
    rule2.__eq__ = lambda a, b: a.id == b

    match1 = Mock()
    match2 = Mock()
    mock_light_search.return_value = [match1, match2]

    mock_es_search.return_value = {"hits": {"hits": [
        {"_source": {"rule": rule1, "matches": {"apk_id": f"{sha256}"}}},
        {"_source": {"rule": rule2, "matches": {"apk_id": ""}}},
    ]}}
    mock_yara.objects.filter.return_value = [rule1, rule2]
    mock_yara.get_es_index_names.return_value = 'yara_matches_public', f'yara_matches_private_{user.id}'

    rules = RulesService.get_rules(user)
    assert rules == [
        {
            "matches":
                [{
                    "matches": {"apk_id": f"{sha256}"},
                    "rule": rule1,
                    "sample": [
                        match1, match2
                    ],
                }],
                'matching_date': '',
                'rule': rule1
        },
        {
            "matches":
                [{
                    "matches": {"apk_id": ""},
                    "rule": rule2,
                    "sample": [
                        match1, match2
                    ],
                }],
            'matching_date': '',
            'rule': rule2
        },
    ]
    mock_yara.objects.filter.assert_called_once()
    mock_light_search.assert_called()
