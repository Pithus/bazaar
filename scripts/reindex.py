# docker-compose -f production.yml stop django worker
# docker-compose -f production.yml run --rm django python manage.py shell


from django.core.files.storage import default_storage
import json
from django.conf import settings
from elasticsearch import Elasticsearch

es = Elasticsearch([settings.ELASTICSEARCH_HOST], timeout=30, max_retries=5, retry_on_timeout=True)
original_index = settings.ELASTICSEARCH_APK_INDEX
tmp_index = f'{original_index}_tmp'

# Create temporary index
with open('bazaar/es_mappings/apk_analysis.json') as mapping:
    apk_analysis_settings = json.load(mapping)
es.indices.create(index=tmp_index, body=apk_analysis_settings)

# Get all APKs
_, hashes = default_storage.listdir('.')
for hash in hashes:
    if es.exists(original_index, id=hash):
        result = es.get(index=original_index, id=hash)['_source']
        es.index(index=tmp_index, id=hash, body=result)

reindex = {
    "source": {
        "index": tmp_index
    },
    "dest": {
        "index": original_index
    }
}
es.indices.delete(index=original_index)
es.indices.create(index=original_index, body=apk_analysis_settings)
es.reindex(body=reindex)
es.indices.delete(index=tmp_index)
