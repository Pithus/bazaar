import logging

from django.conf import settings
from elasticsearch import Elasticsearch

from bazaar.core.utils import compute_status


class ReportService:

    @staticmethod
    def list_reports() -> []:
        try:
            es = Elasticsearch(settings.ELASTICSEARCH_HOSTS, basic_auth=(settings.ELASTICSEARCH_USER, settings.ELASTICSEARCH_PASSWORD))
            q = {
                "sort": {"analysis_date": "desc"},
                "query": {
                    "match_all": {}
                },
                "_source": ["handle", "apk_hash"]
            }
            reports = []
            for report in es.search(index=settings.ELASTICSEARCH_APK_INDEX, body=q)["hits"]["hits"]:
                reports.append(report["_source"])
        except Exception as e:
            logging.error(e)
            raise
        return reports
    
    @staticmethod
    def get_report(sha256) -> {}:
        try:
            es = Elasticsearch(settings.ELASTICSEARCH_HOSTS, basic_auth=(settings.ELASTICSEARCH_USER, settings.ELASTICSEARCH_PASSWORD))
            report = es.get(index=settings.ELASTICSEARCH_APK_INDEX, id=sha256)['_source']
        except Exception as e:
            logging.error(e)
            raise
        return report

    @staticmethod
    def get_detailed_status(sha256):
        try:
            es = Elasticsearch(settings.ELASTICSEARCH_HOSTS, basic_auth=(settings.ELASTICSEARCH_USER, settings.ELASTICSEARCH_PASSWORD))
            detailed_status = es.get(index=settings.ELASTICSEARCH_TASKS_INDEX, id=sha256)['_source']
        except Exception as e:
            logging.error(e)
            raise
        return detailed_status

    @staticmethod
    def get_status(sha256) -> {}:
        try:
            detailed_status = ReportService.get_detailed_status(sha256)
            report_status = compute_status(detailed_status)
        except Exception as e:
            logging.error(e)
            raise
        return report_status
    
    @staticmethod
    def get_example() -> {}:
        try:
            es = Elasticsearch(settings.ELASTICSEARCH_HOSTS, basic_auth=(settings.ELASTICSEARCH_USER, settings.ELASTICSEARCH_PASSWORD))
            q = {
                "size": 1,
                "sort": {"analysis_date": "desc"},
                "query": {
                    "match_all": {}
                },
            }
            example = es.search(index=settings.ELASTICSEARCH_APK_INDEX, body=q)['hits']['hits'][0]['_source']
        except Exception as e:
            logging.error(e)
            raise
        return example