from django.conf import settings
from django.core.management.base import BaseCommand, CommandError
from elasticsearch import Elasticsearch


query = {
   "query": {
      "match_all": {}
   },
   "sort" : [{ "analysis_date" : {"order" : "desc"}}],
   "size": 500
}


class Command(BaseCommand):
    help = 'List existing reports'

    def add_arguments(self, parser):
        pass

    def handle(self, *args, **options):
        es = Elasticsearch(settings.ELASTICSEARCH_HOSTS)
        reports = es.search(index=settings.ELASTICSEARCH_TASKS_INDEX, body=query)['hits']['hits']
        for report in reports:
            id = report['_id']
            source = report['_source']
            analysis_date = report['_source']['analysis_date']
            print(f'{id} - {analysis_date}')
            for k,v in source.items():
                if k == 'analysis_date':
                    continue
                if v != 2:
                    print(f'\t🚫​ {k}: {v}')
                else:
                    print(f'\t✅ {k}: {v}')

