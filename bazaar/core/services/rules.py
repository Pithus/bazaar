import logging

from django.conf import settings
from elasticsearch import Elasticsearch

from bazaar.core.models import Yara


def get_rules(user):
    es = Elasticsearch(settings.ELASTICSEARCH_HOSTS, basic_auth=(settings.ELASTICSEARCH_USER, settings.ELASTICSEARCH_PASSWORD))
    yara_rules = Yara.objects.filter(owner=user)
    public_es_index, private_es_index = Yara.get_es_index_names(user)
    q = {
    'query': {
            'terms': {
                'owner': [user.id]
            }
        },
        'size': 5000,
    }

    public_matches, private_matches = None, None
    try:
        private_matches = es.search(index=private_es_index, body=q)['hits']['hits']
    except:
        pass

    try:
        public_matches = es.search(index=public_es_index, body=q)['hits']['hits']
    except:
        pass

    my_rules = []
    for rule in yara_rules:
        my_rule = {
            'rule': rule,
            'matching_date': '',
            'matches': [],
        }
        if rule.is_private and private_matches:
            for match in private_matches:
                if match['_source']['rule'] == str(rule.id):
                    m = match['_source']
                    m['sample'] = SearchService.light_sample_search(match['_source']['matches']['apk_id'])
                    my_rule['matches'].append(m)
        elif not rule.is_private and public_matches:
            for match in public_matches:
                if match['_source']['rule'] == str(rule.id):
                    m = match['_source']
                    m['sample'] = SearchService.light_sample_search(match['_source']['matches']['apk_id'])
                    my_rule['matches'].append(m)
        my_rules.append(my_rule)

    return my_rules


def delete_es_matches(user, rule):
    es = Elasticsearch(settings.ELASTICSEARCH_HOSTS, basic_auth=(settings.ELASTICSEARCH_USER, settings.ELASTICSEARCH_PASSWORD))
    public_es_index, private_es_index = Yara.get_es_index_names(user)
    q = {'query': {
        'match': {
            'rule': rule.id,
        }
    }}
    if rule.is_private:
        try:
            es.delete_by_query(index=private_es_index, body=q)
        except Exception as e:
            logging.error(e)
            raise e
    elif not rule.is_private:
        try:
            es.delete_by_query(index=public_es_index, body=q)
        except Exception as e:
            logging.error(e)
            raise e
