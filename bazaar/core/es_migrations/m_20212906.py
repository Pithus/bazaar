from django.conf import settings
from elasticsearch import Elasticsearch
import json

from elasticsearch.helpers.actions import scan


def do():
    es = Elasticsearch(settings.ELASTICSEARCH_HOSTS)

    # Update the index mapping
    mapping = json.load(open('bazaar/es_mappings/apk_analysis.json'))
    es.indices.put_mapping(index=settings.ELASTICSEARCH_APK_INDEX, body=mapping.get('mappings'))

    # Populate the `vt_report` field
    for vt_report in scan(es,
         query={"query": {"match_all": {}}},
         index=settings.ELASTICSEARCH_VT_INDEX,
         ):
        _id = vt_report.get('_source').get('attributes').get('sha256')
        try:
            es.update(settings.ELASTICSEARCH_APK_INDEX, id=_id, body={'doc': {'vt_report': vt_report.get('_source')}})
        except Exception as e:
            print(e)


if __name__ == '__main__':
    do()
