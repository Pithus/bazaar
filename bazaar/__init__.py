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
            # 'analysis': {
            #     'analyzer': {
            #         'analyzer_case_insensitive': {
            #             'tokenizer': 'keyword',
            #             'filter': 'lowercase'
            #         }
            #     }
            # }
        }
    }
}

index_mappings = {
    'mappings': {
        'default': {
            'properties': {
                'apk_hash': {
                    'type': 'text',
                    'normalizer': 'to_lowercase'
                }
            }
        }
    }
}

es = Elasticsearch([settings.ELASTICSEARCH_HOST])
try:
    es.indices.create(index=settings.ELASTICSEARCH_APK_INDEX)
except:
    pass

# es.indices.close(index=settings.ELASTICSEARCH_APK_INDEX)
es.indices.put_settings(index_settings, index=settings.ELASTICSEARCH_APK_INDEX)
# es.indices.open(index=settings.ELASTICSEARCH_APK_INDEX)
# es.indices.refresh(index=settings.ELASTICSEARCH_APK_INDEX)

