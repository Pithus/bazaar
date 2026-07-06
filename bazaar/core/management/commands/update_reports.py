from time import sleep
import logging
from django.core.management.base import BaseCommand, CommandError
from elasticsearch.helpers.actions import scan

from bazaar.core.modules import (
    androcfg,
    apkid,
    exodus,
    malware_bazaar,
    mobsf,
    pithus,
    quarkengine,
    similarity,
    threat_hunting,
    virus_total,
)

class Command(BaseCommand):
    help = 'Update existing reports'

    def add_arguments(self, parser):
        parser.add_argument('hash', type=str)
        parser.add_argument('tasks', type=str)

    def handle(self, *args, **options):
        sha256 = options['hash']
        tasks = options['tasks']
        reports = []
        if '*' in sha256:
            for report in scan(es,
                                  query={"query": {"match_all": {}},"_source": ["uploaded_at", "sha256"]},
                                  index=settings.ELASTICSEARCH_APK_INDEX,
                                  ):
                reports.append(report['_source'])

            reports = sorted(reports, key=lambda x: x.get('uploaded_at'), reverse=True)
            counter = 1
            for r in reports:
                _id = r.get('sha256')
                _date = r.get('uploaded_at')
                print(f'Progress -- {counter}/{len(reports)} -- {_id} -- {_date}')
                counter += 1
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
                async_task(mobsf.analysis, sha256)
            if 'b' in tasks:
                print(f'Start malware_bazaar_analysis for {sha256}')
                malware_bazaar.analysis(sha256)
            if 'f' in tasks:
                print(f'Start frosting_analysis for {sha256}')
                pithus.frosting_analysis(sha256)
            if 'v' in tasks:
                print(f'Start vt_analysis for {sha256}')
                vt.analysis(sha256)
                sleep(15)
            if 'a' in tasks:
                print(f'Start apkid_analysis for {sha256}')
                async_task(apkid.analysis, sha256)
            if 's' in tasks:
                print(f'Start ssdeep_analysis for {sha256}')
                similarity.analysis(sha256)
            if 'c' in tasks:
                print(f'Start extract_classes for {sha256}')
                async_task(pithus.extract_classes, sha256)
            if 'q' in tasks:
                print(f'Start quark_analysis for {sha256}')
                async_task(quarkengine.analysis, sha256)
            if 'g' in tasks:
                print(f'Start andro_cfg for {sha256}')
                andro_cfg(sha256, force=True)
            if 'y' in tasks:
                print(f'Start yara_analysis for {sha256}')
                threat_hunting.yara_analysis(sha256)

        except Exception as e:
            logging.exception(e)
            pass
