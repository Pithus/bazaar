# docker-compose -f production.yml stop django worker
# docker-compose -f production.yml run --rm django python manage.py shell

import json

from django.conf import settings
from elasticsearch import Elasticsearch

es = Elasticsearch([settings.ELASTICSEARCH_HOST], timeout=30, max_retries=5, retry_on_timeout=True)
original_index = settings.ELASTICSEARCH_APK_INDEX
tmp_index = f'{original_index}_tmp'

# Set the Elasticsearch endpoint URL and the name of the index
INDEX_NAME = "apk_analysis"

# Set the old field name and the new field name
OLD_FIELD_NAME = "ssdeed_hash"
NEW_FIELD_NAME = "ssdeep_hash"
# Set the old field name and the new field name

# Load the new mapping from the provided JSON file
with open("bazaar/es_mappings/apk_analysis.json") as f:
    new_mapping = json.load(f)
es.indices.create(index=tmp_index, body=new_mapping)

# Update the mapping for the field
new_mapping["mappings"]["properties"]["andro_cfg"]["properties"]["rules"]["properties"]["findings"]["properties"][NEW_FIELD_NAME] = {
        "type": "keyword",
        "index": True
        }

del new_mapping["mappings"]["properties"]["andro_cfg"]["properties"]["rules"]["properties"]["findings"]["properties"][OLD_FIELD_NAME]

reindex = {
    "source": {
        "index": INDEX_NAME
    },
    "dest": {
        "index": f"{INDEX_NAME}_new"
    },
    "script": {
        "source": f"ctx._source.remove('{OLD_FIELD_NAME}'); ctx._source.{NEW_FIELD_NAME} = ctx._source.remove('{OLD_FIELD_NAME}')"
    }
}

es.indices.delete(index=original_index)
es.indices.create(index=original_index, body=new_mapping)
es.reindex(body=reindex)
es.indices.delete(index=tmp_index)