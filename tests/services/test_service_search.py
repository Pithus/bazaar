from unittest.mock import patch

from ..conftest import sha256

from bazaar.core.services import SearchService


@patch("bazaar.core.services.search.Elasticsearch.search")
def test_search(mock_es_search):
    fake_results = ['fake', 'test', 'results']
    mock_es_search.return_value = fake_results
    assert SearchService.search('fake query') == fake_results


@patch("bazaar.core.services.search.Elasticsearch.search")
def test_light_sample_search(mock_es_search):
    fake_results = ['fake', 'test', 'results']
    mock_es_search.return_value = {"hits": {"hits": [{"_source": fake_results}]}}
    assert SearchService.light_sample_search('fake query') == [{"source": fake_results}]


@patch("bazaar.core.services.search.get_matching_items_by_dexofuzzy")
@patch("bazaar.core.services.search.get_matching_items_by_ssdeep")
@patch("bazaar.core.services.search.get_matching_items_by_ssdeep_func")
def test_similarity_search(mock_func, mock_ssdeep, mock_dexo):
    fake_results = ['result1', 'result2', 'result3']
    mock_dexo.return_value = fake_results
    mock_ssdeep.return_value = fake_results
    mock_func.return_value = fake_results
    algorithms_map = {
        'dexofuzzy': mock_dexo,
        'ssdeep': mock_ssdeep,
        'func_hash': mock_func,
    }
    search_hash = 'fake_hash'

    for alg in algorithms_map.keys():
        result = SearchService.similarity_search(search_hash, alg, sha256)
        assert result == fake_results
        algorithms_map[alg].assert_called_once()
