__version__ = "0.1.0"
__version_info__ = tuple(
    [
        int(num) if num.isdigit() else num
        for num in __version__.replace("-", ".", 1).split(".")
    ]
)

from django.conf import settings
from elasticsearch import Elasticsearch

index_settings = {
    'settings': {
        'index': {
            'mapping': {
                'total_fields': {
                    'limit': '65635'
                }
            },
            'highlight': {
                'max_analyzed_offset': '60000000'
            }
            # 'analysis': {
            #     'analyzer': {
            #         'analyzer_case_insensitive': {
            #             'tokenizer': 'keyword',
            #             'filter': 'lowercase'
            #         }
            #     }
            # }
        }
    },
    "mappings": {
        "properties": {
            "java_classes": {
                "type": "text",
                "term_vector": "with_positions_offsets"
            },
            "analysis_date": {
                "type": "date"
            }
        }
    }
}

index_mappings = {
    "properties": {
        "java_classes": {
            "type": "keyword",
            "term_vector": "with_positions_offsets"
        },
        "analysis_date": {
            "type": "date"
        }
    }
}

es = Elasticsearch([settings.ELASTICSEARCH_HOST])
try:
    es.indices.create(index=settings.ELASTICSEARCH_APK_INDEX)
    es.indices.put_settings(body=index_settings, index=settings.ELASTICSEARCH_APK_INDEX)
    # es.indices.close(index=settings.ELASTICSEARCH_APK_INDEX)
    # es.indices.put_settings(body=index_settings, index=settings.ELASTICSEARCH_APK_INDEX)
    es.indices.put_mapping(body=index_mappings, index=settings.ELASTICSEARCH_APK_INDEX, doc_type='_doc', include_type_name=True)
    # es.indices.open(index=settings.ELASTICSEARCH_APK_INDEX)
    # es.indices.refresh(index=settings.ELASTICSEARCH_APK_INDEX)
except Exception as e:
    print(e)
    pass
