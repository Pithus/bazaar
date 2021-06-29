from time import sleep
import logging
from django.core.management.base import BaseCommand, CommandError
from elasticsearch.helpers.actions import scan

from bazaar.core.tasks import *


class Command(BaseCommand):
    help = 'Update existing reports'

    def add_arguments(self, parser):
        parser.add_argument('hash', type=str)
        parser.add_argument('tasks', type=str)

    def handle(self, *args, **options):
        sha256 = options['hash']
        tasks = options['tasks']

        if '*' in sha256:
            for report in scan(es,
                                  query={"query": {"match_all": {}}},
                                  index=settings.ELASTICSEARCH_APK_INDEX,
                                  ):
                _id = report.get('_source').get('sha256')
                try:
                    self._handle_sample(_id, tasks)
                except Exception as e:
                    print(e)
        else:
            self._handle_sample(sha256, tasks)

    def _handle_sample(self, sha256, tasks):
        try:
            if 'm' in tasks:
                print(f'Start mobsf_analysis for {sha256}')
                async_task(mobsf_analysis, sha256)
            if 'b' in tasks:
                print(f'Start malware_bazaar_analysis for {sha256}')
                malware_bazaar_analysis(sha256)
            if 'f' in tasks:
                print(f'Start frosting_analysis for {sha256}')
                frosting_analysis(sha256)
            if 'v' in tasks:
                print(f'Start vt_analysis for {sha256}')
                vt_analysis(sha256)
                sleep(15)
            if 'a' in tasks:
                print(f'Start apkid_analysis for {sha256}')
                async_task(apkid_analysis, sha256)
            if 's' in tasks:
                print(f'Start ssdeep_analysis for {sha256}')
                ssdeep_analysis(sha256)
            if 'c' in tasks:
                print(f'Start extract_classes for {sha256}')
                async_task(extract_classes, sha256)
            if 'q' in tasks:
                print(f'Start quark_analysis for {sha256}')
                async_task(quark_analysis, sha256)
            if 'g' in tasks:
                print(f'Start andro_cfg for {sha256}')
                andro_cfg(sha256)
            if 'y' in tasks:
                print(f'Start yara_analysis for {sha256}')
                yara_analysis(sha256)

        except Exception as e:
            logging.exception(e)
            pass
