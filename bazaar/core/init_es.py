import json

from django.conf import settings
from elasticsearch import Elasticsearch


def init_es():
    es = Elasticsearch(settings.ELASTICSEARCH_HOSTS)
    with open('bazaar/es_mappings/apk_analysis.json') as mapping:
        apk_analysis_settings = json.load(mapping)
    try:
        es.indices.create(index=settings.ELASTICSEARCH_GP_INDEX)
        es.indices.create(index=settings.ELASTICSEARCH_TASKS_INDEX)
        es.indices.create(index=settings.ELASTICSEARCH_APK_INDEX, body=apk_analysis_settings)
    except Exception as e:
        print(e)
        pass


def init_fuzzy_match_es():
    index_settings = {
        "settings": {
            "analysis": {
                "analyzer": {
                    "ssdeep_analyzer": {
                        "tokenizer": "ssdeep_tokenizer"
                    }
                },
                "tokenizer": {
                    "ssdeep_tokenizer": {
                        "type": "ngram",
                        "min_gram": 7,
                        "max_gram": 7
                    }
                }
            }
        },
        "mappings": {
            "dynamic": "strict",
            "properties": {
                "chunk_size": {
                    "type": "integer"
                },
                "chunk": {
                    "analyzer": "ssdeep_analyzer",
                    "type": "text"
                },
                "double_chunk": {
                    "analyzer": "ssdeep_analyzer",
                    "type": "text"
                },
                'sha256': {
                    'type': 'keyword'
                }
            }
        }
    }

    es = Elasticsearch(settings.ELASTICSEARCH_HOSTS)
    try:
        es.indices.create(index=settings.ELASTICSEARCH_DEXOFUZZY_APK_INDEX, body=index_settings)
        es.indices.create(index=settings.ELASTICSEARCH_SSDEEP_APK_INDEX, body=index_settings)
        es.indices.create(index=settings.ELASTICSEARCH_SSDEEP_MANIFEST_INDEX, body=index_settings)
    except Exception as e:
        print(e)
        pass
